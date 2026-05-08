// auth-audit is the standalone audit pipeline tool for the tokyo3-auth IdP.
//
// Subcommands:
//
//	auth-audit consume   Read audit events from NATS JetStream and upsert them
//	                     into the dedicated audit database. Runs until SIGINT/SIGTERM.
//	auth-audit query     Query the audit database and print matching entries.
//	auth-audit version   Print version information.
//
// # Environment variables (both subcommands share the database vars)
//
//	AUTH_AUDIT_DATABASE_URL   Postgres DSN with DDL + DML + SELECT rights on the
//	                          audit database; mutually exclusive with AUTH_AUDIT_DB_PATH.
//	AUTH_AUDIT_DB_PATH        SQLite path (default for consume: audit.db).
//	AUTH_AUDIT_DB_CERT        Client cert PEM path for audit DB mTLS.
//	AUTH_AUDIT_DB_KEY         Client key PEM path. Required when AUTH_AUDIT_DB_CERT is set.
//	AUTH_AUDIT_DB_CA          CA cert PEM path for verifying the audit DB server cert.
//
// # consume-only environment variables
//
//	AUTH_AUDIT_NATS_URL    NATS server URL (required for consume).
//	AUTH_AUDIT_NATS_CERT   Consumer client certificate PEM path (mTLS).
//	AUTH_AUDIT_NATS_KEY    Consumer client key PEM path.
//	AUTH_AUDIT_NATS_CA     CA certificate PEM path for NATS server verification.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/abagile/tokyo3-auth/internal/audit"
	auditpg "github.com/abagile/tokyo3-auth/internal/audit/postgres"
	auditsqlite "github.com/abagile/tokyo3-auth/internal/audit/sqlite"
	"github.com/abagile/tokyo3-base/applog"
	bnats "github.com/abagile/tokyo3-base/nats"
	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/spf13/cobra"
)

const consumerName = "audit-db-writer"

func main() {
	log, _ := applog.AppLogger("auth-audit", applog.WithStdout())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	root := &cobra.Command{
		Use:           "auth-audit",
		Short:         "Audit pipeline tool for the tokyo3-auth IdP",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newConsumeCmd(ctx, log), newQueryCmd(ctx), newVersionCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// openAuditDB opens the audit database from AUTH_AUDIT_DATABASE_URL (Postgres)
// or AUTH_AUDIT_DB_PATH (SQLite). The returned audit.Store is used for migrations,
// writes, and queries — the single credential requires DDL + INSERT + SELECT rights.
// defaultPath is used when AUTH_AUDIT_DB_PATH is unset; pass "" to require an
// explicit path (query command) or a fallback (consume command).
func openAuditDB(log *slog.Logger, defaultPath string) (audit.Store, error) {
	if dsn := os.Getenv("AUTH_AUDIT_DATABASE_URL"); dsn != "" {
		tlsCfg, err := btls.FromFiles(
			os.Getenv("AUTH_AUDIT_DB_CERT"),
			os.Getenv("AUTH_AUDIT_DB_KEY"),
			os.Getenv("AUTH_AUDIT_DB_CA"),
		)
		if err != nil {
			return nil, fmt.Errorf("audit db TLS: %w", err)
		}
		if err := auditpg.Migrate(dsn, tlsCfg); err != nil {
			return nil, fmt.Errorf("audit db migration: %w", err)
		}
		if tlsCfg != nil {
			log.Info("audit db: postgres with mTLS client cert")
		} else {
			log.Info("audit db: postgres")
		}
		return auditpg.Open(dsn, tlsCfg)
	}
	path := os.Getenv("AUTH_AUDIT_DB_PATH")
	if path == "" {
		if defaultPath == "" {
			return nil, fmt.Errorf("AUTH_AUDIT_DATABASE_URL or AUTH_AUDIT_DB_PATH is required")
		}
		path = defaultPath
	}
	log.Info("audit db: sqlite", "path", path)
	return auditsqlite.Open(path)
}

// ── version ───────────────────────────────────────────────────────────────────

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			version, commit := readBuildInfo()
			fmt.Printf("auth-audit %s (commit %s)\n", version, commit)
		},
	}
}

// readBuildInfo extracts module version and VCS commit from the binary's
// embedded build info. Returns ("dev","unknown") for an `go run`-style build.
func readBuildInfo() (version, commit string) {
	version = "dev"
	commit = "unknown"
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			commit = s.Value
			if len(commit) > 12 {
				commit = commit[:12]
			}
		}
	}
	return
}

// ── consume ───────────────────────────────────────────────────────────────────

func newConsumeCmd(ctx context.Context, log *slog.Logger) *cobra.Command {
	return &cobra.Command{
		Use:   "consume",
		Short: "Read audit events from NATS JetStream and write to the audit database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConsume(ctx, log)
		},
	}
}

func runConsume(ctx context.Context, log *slog.Logger) error {
	adb, err := openAuditDB(log, "audit.db")
	if err != nil {
		return fmt.Errorf("open audit db: %w", err)
	}
	defer adb.Close()

	nc, err := connectConsumerNATS(log)
	if err != nil {
		return fmt.Errorf("nats connect: %w", err)
	}
	defer nc.Drain()

	js, err := jetstream.New(nc)
	if err != nil {
		return fmt.Errorf("jetstream client: %w", err)
	}

	// Ensure the auth_audit stream exists. In production the natsbox sidecar
	// (or NATS operator) provisions the stream; CreateOrUpdateStream is
	// idempotent so it is safe to call here as a convenience for development
	// and first-run scenarios.
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       audit.StreamName,
		Subjects:   []string{audit.Subject},
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
		MaxAge:     audit.StreamMaxAge,
		DenyDelete: true,
		DenyPurge:  true,
	})
	if err != nil {
		return fmt.Errorf("ensure audit stream: %w", err)
	}

	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       consumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: audit.Subject,
		MaxAckPending: 256,
	})
	if err != nil {
		return fmt.Errorf("create audit consumer: %w", err)
	}

	log.Info("consume: running", "stream", audit.StreamName, "consumer", consumerName)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		batch, err := cons.Fetch(64, jetstream.FetchMaxWait(2*time.Second))
		if err != nil {
			log.Warn("consume: fetch error", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}

		for msg := range batch.Messages() {
			var e audit.Entry
			if err := json.Unmarshal(msg.Data(), &e); err != nil {
				// Malformed payload: ack to skip rather than loop forever on redelivery.
				log.Error("consume: unmarshal failed, discarding", "err", err, "data", string(msg.Data()))
				msg.Ack()
				continue
			}
			if err := adb.UpsertAuditLog(ctx, e); err != nil {
				log.Error("consume: upsert failed, nacking", "err", err)
				msg.Nak()
				continue
			}
			msg.Ack()
		}
		if err := batch.Error(); err != nil {
			log.Warn("consume: batch error", "err", err)
		}
	}
}

func connectConsumerNATS(log *slog.Logger) (*nats.Conn, error) {
	url := os.Getenv("AUTH_AUDIT_NATS_URL")
	if url == "" {
		return nil, fmt.Errorf("AUTH_AUDIT_NATS_URL is required for consume")
	}
	certFile := os.Getenv("AUTH_AUDIT_NATS_CERT")
	keyFile := os.Getenv("AUTH_AUDIT_NATS_KEY")
	caFile := os.Getenv("AUTH_AUDIT_NATS_CA")
	if certFile != "" {
		log.Info("consume: NATS mTLS enabled", "url", url)
	} else {
		log.Warn("consume: AUTH_AUDIT_NATS_CERT not set — connecting without mTLS (not for production)")
	}
	return bnats.Dial(url, certFile, keyFile, caFile)
}

// ── query ─────────────────────────────────────────────────────────────────────

func newQueryCmd(ctx context.Context) *cobra.Command {
	var userID, clientID, action string
	var limit int

	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query the audit database and print matching entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuery(ctx, userID, clientID, action, limit)
		},
	}
	cmd.Flags().StringVar(&userID, "user-id", "", "Filter by user UUID")
	cmd.Flags().StringVar(&clientID, "client-id", "", "Filter by OAuth2 client UUID")
	cmd.Flags().StringVar(&action, "action", "", "Filter by action (e.g. auth.login)")
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum entries to return (1–500)")
	return cmd
}

func runQuery(ctx context.Context, userID, clientID, action string, limit int) error {
	if limit < 1 || limit > 500 {
		return fmt.Errorf("--limit must be between 1 and 500")
	}

	log, _ := applog.AppLogger("auth-audit", applog.WithStdout())
	db, err := openAuditDB(log, "")
	if err != nil {
		return fmt.Errorf("open audit db: %w", err)
	}
	defer db.Close()

	rows, err := db.ListAuditLogs(ctx, audit.Filter{
		UserID:   userID,
		ClientID: clientID,
		Action:   action,
		Limit:    limit,
	})
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	if len(rows) == 0 {
		fmt.Println("No audit entries found.")
		return nil
	}

	fmt.Printf("%-22s  %-26s  %-10s  %s\n", "TIME", "ACTION", "USER", "IP")
	for _, r := range rows {
		user := "-"
		if r.UserID != "" {
			user = r.UserID
			if len(user) >= 8 {
				user = user[:8] + "…"
			}
		}
		ip := "-"
		if r.IP != "" {
			ip = r.IP
		}
		fmt.Printf("%-22s  %-26s  %-10s  %s\n",
			r.CreatedAt.Local().Format("2006-01-02 15:04:05"),
			r.Action, user, ip)
	}
	return nil
}
