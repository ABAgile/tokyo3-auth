package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/abagile/tokyo3-auth/internal/audit"
	"github.com/abagile/tokyo3-base/journal/jetstream"
	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/spf13/cobra"
)

// auditCmd is the umbrella for read-only access to the audit JetStream
// journal. The journal itself is the authoritative store; this command is
// just a CLI viewer that reuses the same journal/jetstream.Source the
// portal admin live-tail page uses, formatted for terminal output.
func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Read events from the audit JetStream journal",
	}
	cmd.AddCommand(auditQueryCmd())
	return cmd
}

// auditQueryCmd implements `authd audit query [--limit N]`. Connects to NATS
// via AUTHD_NATS_URL + AUTHD_NATS_CERT/KEY/CA, replays the most recent --limit
// records as one JSON object per line on stdout, then exits when either the
// limit is reached or the backfill stalls for the idle-timeout window.
//
// Filtering (--action, --user, --client, --since) is intentionally not
// surfaced yet; add it as flags here and corresponding wire/predicate
// support when the use case demands.
func auditQueryCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Print the most recent N audit events from the journal",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 1 || limit > 1000 {
				return fmt.Errorf("--limit must be between 1 and 1000")
			}
			return runAuditQuery(cmd.Context(), limit)
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 100, "How many recent records to print (1–1000)")
	return cmd
}

func runAuditQuery(ctx context.Context, limit int) error {
	url := os.Getenv("AUTHD_NATS_URL")
	if url == "" {
		return fmt.Errorf("AUTHD_NATS_URL is not set — cannot query audit journal")
	}
	tlsCfg, err := btls.FromFiles(
		os.Getenv("AUTHD_NATS_CERT"),
		os.Getenv("AUTHD_NATS_KEY"),
		os.Getenv("AUTHD_NATS_CA"),
	)
	if err != nil {
		return fmt.Errorf("nats audit TLS: %w", err)
	}
	src, err := jetstream.NewSource(jetstream.SourceConfig{
		URL:        url,
		StreamName: audit.StreamName,
		Subject:    audit.Subject,
		TLS:        tlsCfg,
	})
	if err != nil {
		return fmt.Errorf("open audit source: %w", err)
	}
	defer src.Close()

	// Bound the whole call so a hung stream can't pin the CLI forever.
	queryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	msgs, err := src.Subscribe(queryCtx, limit, 0)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	// Idle-stop: after delivering the backfill window the consumer would tail
	// new records indefinitely, but a `query` is a one-shot read. Exit when
	// either --limit records are seen or the stream has gone quiet for
	// idleTimeout — whichever comes first.
	const idleTimeout = 2 * time.Second
	idle := time.NewTimer(idleTimeout)
	defer idle.Stop()

	count := 0
	for count < limit {
		select {
		case <-queryCtx.Done():
			return nil
		case <-idle.C:
			return nil
		case m, ok := <-msgs:
			if !ok {
				return nil
			}
			// Each Msg.Data is already a wire-ready JSON audit.Entry —
			// pass through verbatim, one per line, for grep/jq pipelines.
			if _, err := os.Stdout.Write(m.Data); err != nil {
				return err
			}
			if _, err := os.Stdout.Write([]byte("\n")); err != nil {
				return err
			}
			count++
			if !idle.Stop() {
				<-idle.C
			}
			idle.Reset(idleTimeout)
		}
	}
	return nil
}
