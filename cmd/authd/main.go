// Command authd is the tokyo3-auth Identity Provider server.
//
// Required env vars:
//
//	AUTHD_MASTER_KEY               64-char hex master key (run `authd
//	                               keygen`).
//	AUTHD_ISSUER                   Public issuer URL — used in OIDC
//	                               discovery and JWT iss claim.
//	AUTHD_DATABASE_URL             Runtime Postgres DSN (DML-only role).
//
// Optional:
//
//	AUTHD_ADMIN_DATABASE_URL       Admin DSN used for schema migrations
//	                               (DDL). Falls back to AUTHD_DATABASE_URL
//	                               when unset (both `serve` and `migrate`
//	                               subcommands).
//	AUTHD_ADDR                     HTTPS listen address (default: :8443).
//	AUTHD_ALLOW_REGISTRATION       Set to "true" to enable self-registration
//	                               at /register.
//	AUTHD_PROVISION_SYNC_INTERVAL  Period for the background full-sync
//	                               goroutine that re-pushes every user/group
//	                               to every enabled integration (defaults to
//	                               1h; set to 0 or a negative duration to
//	                               disable). Belt-and-suspenders for the
//	                               event-driven push path: catches drift
//	                               from missed events, downstream restores,
//	                               and split-brain after restarts. Each tick
//	                               is idempotent on the downstream
//	                               (PATCH-or-POST on users, full-list PUT on
//	                               groups).
//	AUTHD_AWSFED_REAP_INTERVAL     Period for the AWS federation revocation
//	                               reaper (defaults to 6h; 0 or negative
//	                               disables it). Trims aws_revoked_users
//	                               entries past the role's
//	                               MaxSessionDuration and re-pushes the
//	                               trimmed inline policy. No-op when no
//	                               aws_federation integration is enabled.
//	AUTHD_AWS_AUDIENCE             The single `aud` claim value emitted on
//	                               every JWT minted for AWS console / CLI
//	                               federation. Registered once per AWS
//	                               account as the IAM identity provider's
//	                               audience. Empty disables AWS federation
//	                               (the portal and the /aws/credentials
//	                               endpoint return 503). Trust policies gate
//	                               per-role assumption via
//	                               aws:RequestTag/<key> conditions instead
//	                               of per-role audiences. See the AWS OIDC
//	                               Federation section in README for setup.
//
// TLS — the API always serves HTTPS (IdP requirement):
//
//	AUTHD_API_CERT                 Path to server TLS certificate PEM
//	                               (hot-reloaded; the file's mtime is polled
//	                               at most once per second across
//	                               handshakes, so rotations land within
//	                               ~1s).
//	AUTHD_API_KEY                  Path to server TLS private key PEM. Must
//	                               be paired with AUTHD_API_CERT. If neither
//	                               is set, an ephemeral self-signed cert is
//	                               generated (dev only).
//	AUTHD_API_CLIENT_CA            Optional CA PEM for client cert
//	                               verification (mTLS).
//
// Workload CA (single root for every internal mTLS channel — DB, NATS, SCIM):
//
//	AUTHD_WORKLOAD_CA              CA PEM that signs every internal workload
//	                               cert auth talks to (Postgres, NATS,
//	                               downstream SCIM endpoints). Used as the
//	                               fallback for AUTHD_DB_CA /
//	                               AUTHD_ADMIN_DB_CA / AUTHD_NATS_CA /
//	                               AUTHD_SCIM_MTLS_CA when any of those is
//	                               unset. Leave the per-channel CA vars
//	                               empty in deployments that issue all
//	                               internal certs from one workload CA; set
//	                               the per-channel vars when stricter
//	                               separation is needed.
//
// Database mTLS (optional, used together with cert-auth Postgres):
//
//	AUTHD_DB_CERT                  Client certificate PEM for the runtime
//	                               auth→postgres connection.
//	AUTHD_DB_KEY                   Client key PEM (must be paired with
//	                               AUTHD_DB_CERT).
//	AUTHD_DB_CA                    CA PEM for verifying the postgres server
//	                               certificate. Falls back to
//	                               AUTHD_WORKLOAD_CA when unset.
//	AUTHD_ADMIN_DB_CERT            Client certificate PEM for the admin
//	                               (migration) connection. Falls back to
//	                               AUTHD_DB_CERT when unset (suitable for
//	                               dev/single-role setups; production should
//	                               issue a separate DDL credential).
//	AUTHD_ADMIN_DB_KEY             Client key PEM. Falls back to
//	                               AUTHD_DB_KEY.
//	AUTHD_ADMIN_DB_CA              CA PEM. Falls back to AUTHD_DB_CA →
//	                               AUTHD_WORKLOAD_CA.
//
// Outbound mTLS (used by app_integrations rows with auth_mode=mtls):
//
//	AUTHD_SCIM_MTLS_CERT           Client cert PEM that auth presents to
//	                               mTLS-mode SCIM downstreams. Hot-reloaded
//	                               (mtime polled at most once per second
//	                               across SCIM requests).
//	AUTHD_SCIM_MTLS_KEY            Client key PEM. Required iff
//	                               AUTHD_SCIM_MTLS_CERT is set.
//	AUTHD_SCIM_MTLS_CA             Optional CA bundle for verifying
//	                               downstream servers. Empty falls back to
//	                               AUTHD_WORKLOAD_CA, then to the system
//	                               root pool. A single cert/key pair is
//	                               shared across every mTLS integration.
//
// Audit log shipping (publishes events to NATS JetStream stream "auth_audit"):
//
//	AUTHD_NATS_URL                 NATS server URL (e.g. nats://nats:4222 or
//	                               tls://nats:4222). Empty disables
//	                               JetStream publishing (NoopSink).
//	AUTHD_NATS_CERT                Publisher client certificate PEM path
//	                               (mTLS).
//	AUTHD_NATS_KEY                 Publisher client key PEM path. Required
//	                               iff AUTHD_NATS_CERT is set.
//	AUTHD_NATS_CA                  CA certificate PEM path for verifying the
//	                               NATS server cert. Falls back to
//	                               AUTHD_WORKLOAD_CA when unset.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/api"
	"github.com/abagile/tokyo3-auth/internal/audit"
	internaljwt "github.com/abagile/tokyo3-auth/internal/jwt"
	"github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/policy"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/provision/awsfed"
	"github.com/abagile/tokyo3-auth/internal/provision/iam"
	scimprov "github.com/abagile/tokyo3-auth/internal/provision/scim"
	"github.com/abagile/tokyo3-auth/internal/store/postgres"
	"github.com/abagile/tokyo3-base/applog"
	creds "github.com/abagile/tokyo3-base/auth/creds"
	"github.com/abagile/tokyo3-base/cli"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/abagile/tokyo3-base/envutil"
	"github.com/abagile/tokyo3-base/guard"
	btls "github.com/abagile/tokyo3-base/tls"
	"github.com/abagile/tokyo3-base/tls/reloader"
	"github.com/abagile/tokyo3-base/version"
	"github.com/spf13/cobra"
)

const appName = "authd"

// Version is the build version, overwritten via -ldflags "-X main.Version=…"
// in release builds; version.Resolve falls back to runtime/debug.BuildInfo
// for `go install …@vX.Y.Z` and source-tree builds.
var Version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "authd",
		Short: "tokyo3-auth Identity Provider",
	}
	root.AddCommand(serveCmd(), migrateCmd(), keygenCmd(), adminCmd(), auditCmd(), versionCmd())
	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the build version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.Resolve(Version))
		},
	}
}

// ── serve ─────────────────────────────────────────────────────────────────────

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the IdP HTTP server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe()
		},
	}
}

func runServe() error {
	// cli.App.Setup wires the app logger (with NATS log shipping over the
	// resolved workload identity), a SIGINT/SIGTERM-cancelled context, and
	// the opt-in diagnostics server (AUTHD_DEBUG_ADDR). rt.NATS carries the
	// resolved NATS material (AUTHD_NATS_* falling back to AUTHD_WORKLOAD_*)
	// that the audit sink + source draw from.
	// Cancellable parent so the listener-exit goroutine below can trigger
	// graceful shutdown (rt.Ctx is a child of parentCtx via NotifyContext).
	parentCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := cli.App{Name: appName, EnvPrefix: "AUTHD"}.Setup(parentCtx)
	defer rt.Shutdown()
	log, ctx := rt.Log, rt.Ctx
	log.Info("authd starting", "version", version.Resolve(Version))

	issuer := envutil.MustEnv("AUTHD_ISSUER")
	if rt.DB.URL == "" {
		return fmt.Errorf("AUTHD_DATABASE_URL is required")
	}
	masterKeyHex := envutil.MustEnv("AUTHD_MASTER_KEY")
	addr := envutil.Or("AUTHD_ADDR", ":8443")

	masterKey, err := bcrypto.ParseKEK(masterKeyHex)
	if err != nil {
		return fmt.Errorf("parse master key: %w", err)
	}

	adminDBTLS, err := dbAdminTLS(rt.AdminDB)
	if err != nil {
		return fmt.Errorf("admin db TLS: %w", err)
	}
	dbTLS, err := dbRuntimeTLS(rt.DB)
	if err != nil {
		return fmt.Errorf("db TLS: %w", err)
	}
	outboundTLS, err := outboundTLSFromEnv()
	if err != nil {
		return fmt.Errorf("outbound TLS: %w", err)
	}
	// Audit publisher + reader share rt.NATS material; cli.AuditSink/Source
	// hot-reload the workload cert per handshake and the CA pool on mtime
	// (via tls/reloader), so cert-agentd rotations land without a restart.
	auditSink, err := cli.AuditSink[audit.Entry](rt, audit.Subject)
	if err != nil {
		return fmt.Errorf("audit sink: %w", err)
	}
	defer auditSink.Close()
	auditSource, err := cli.AuditSource(rt, audit.StreamName, audit.Subject)
	if err != nil {
		return fmt.Errorf("audit source: %w", err)
	}
	defer auditSource.Close()

	// Run migrations with the admin DSN, then open the runtime connection.
	if adminDBTLS != nil {
		log.Info("running migrations (mTLS)")
	} else {
		log.Info("running migrations")
	}
	if err := postgres.Migrate(rt.AdminDB.URL, adminDBTLS); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db, err := postgres.OpenWithTLS(rt.DB.URL, dbTLS)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	kp := bcrypto.NewLocalKeyProvider(masterKey)

	signer, err := internaljwt.LoadOrCreate(ctx, db, kp, issuer, internaljwt.Config{})
	if err != nil {
		return fmt.Errorf("jwt signer: %w", err)
	}

	// Derive WebAuthn RPID from issuer URL (AUTHD_WEBAUTHN_RPID overrides).
	rpID, rpOrigins := webAuthnParams(issuer)
	waHandler, err := mfa.NewWAHandler(rpID, "tokyo3-auth", rpOrigins, db)
	if err != nil {
		return fmt.Errorf("webauthn handler: %w", err)
	}

	eng := policy.New(policy.DefaultPCIRules()...)

	if err := autoImportLegacyVaultEnv(ctx, db, kp, log); err != nil {
		log.Error("auto-import legacy vault env", "err", err)
		// Non-fatal: continue with whatever is in the table.
	}

	provReg := provision.NewRegistry(func(ctx context.Context) (*provision.Set, error) {
		return buildProvSet(ctx, db, kp, outboundTLS, log)
	})
	if err := provReg.Reload(ctx); err != nil {
		return fmt.Errorf("load provisioners: %w", err)
	}

	srv, err := api.New(api.Config{
		Store:             db,
		Signer:            signer,
		Policy:            eng,
		WAHandler:         waHandler,
		KP:                kp,
		Provisioners:      provReg,
		OutboundTLS:       outboundTLS,
		Audit:             auditSink,
		AuditSource:       auditSource,
		Issuer:            issuer,
		AWSAudience:       os.Getenv("AUTHD_AWS_AUDIENCE"),
		StepUpMFATTL:      parseDurationEnv("AUTHD_STEP_UP_MFA_TTL"),
		MasterKey:         masterKey,
		Log:               log,
		AllowRegistration: strings.EqualFold(os.Getenv("AUTHD_ALLOW_REGISTRATION"), "true"),
	})
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	tlsCfg, err := buildServerTLS(log)
	if err != nil {
		return fmt.Errorf("server TLS: %w", err)
	}

	httpSrv := &http.Server{
		Addr:      addr,
		Handler:   srv.Routes(),
		TLSConfig: tlsCfg,
		// Slowloris defense: cap how long a client can dribble out
		// request headers / body before the server gives up the
		// connection. WriteTimeout intentionally left at 0 — the SSE
		// audit-tail handler streams indefinitely, and net/http applies
		// WriteTimeout uniformly across the whole response. SSE handlers
		// should use http.ResponseController.SetWriteDeadline per write
		// if per-frame deadlines are needed.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Route TLS handshake errors, broken-pipe writes, and similar
		// http-internal noise into the structured logger so they show
		// up alongside everything else (and ship through the same NATS
		// log subject) instead of dumping naked lines to stderr.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		// BaseContext makes every request inherit from the SIGTERM-aware
		// ctx so long-lived handlers (e.g. /portal/admin/audit/sse, which
		// blocks in select{} on r.Context().Done() and the JetStream
		// iterator) abort promptly on shutdown. Without this, Shutdown
		// would wait its full 10s deadline for each open SSE tab; with
		// it, ctx cancels propagate down the SSE → Source.Subscribe →
		// jetstream consumer chain in milliseconds.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	if interval := provisionSyncInterval(log); interval > 0 {
		guard.Go(log, "provision-sync", func() {
			runPeriodicProvisionSync(ctx, db, provReg, interval, log)
		})
	}
	if interval := awsFedReapInterval(log); interval > 0 {
		guard.Go(log, "awsfed-reaper", func() {
			runAWSFedReaper(ctx, provReg, interval, log)
		})
	}
	guard.Go(log, "device-grant-reaper", func() {
		runDeviceGrantReaper(ctx, db, time.Minute, log)
	})

	log.Info("starting server", "addr", addr, "issuer", issuer, "tls", true)
	go func() {
		// On unexpected listener exit (bind error, fatal TLS config
		// problem, fd exhaustion) signal the main goroutine so the
		// deferred cleanup in runServe — auditSink.Close, db.Close,
		// signer disposal, log-shipping drain — actually runs. An
		// earlier version called os.Exit(1) here, which short-circuited
		// every defer and dropped audit events that were still waiting
		// for a JetStream ack.
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Error("http server exited unexpectedly; initiating graceful shutdown", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()
	log.Info("authd shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "shutdown error: %v\n", err)
	}
	return nil
}

// ── migrate ───────────────────────────────────────────────────────────────────

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			adminMat := cli.App{EnvPrefix: "AUTHD"}.AdminDB()
			if adminMat.URL == "" {
				return fmt.Errorf("AUTHD_ADMIN_DATABASE_URL or AUTHD_DATABASE_URL must be set")
			}
			adminDBTLS, err := dbAdminTLS(adminMat)
			if err != nil {
				return fmt.Errorf("admin db TLS: %w", err)
			}
			if err := postgres.Migrate(adminMat.URL, adminDBTLS); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			fmt.Println("migrations applied successfully")
			return nil
		},
	}
}

// ── keygen ────────────────────────────────────────────────────────────────────

func keygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen",
		Short: "Generate a random 32-byte master key (printed as 64 hex chars)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := bcrypto.GenerateKEK()
			if err != nil {
				return err
			}
			fmt.Println(key)
			return nil
		},
	}
}

// ── admin ─────────────────────────────────────────────────────────────────────

func adminCmd() *cobra.Command {
	admin := &cobra.Command{
		Use:   "admin",
		Short: "Administrative operations",
	}
	admin.AddCommand(adminUserCmd(), adminSyncCmd())
	return admin
}

// adminSyncCmd backfills downstream provisioning targets from auth's user/group
// tables. Use after a fresh deployment, after restoring auth from backup, or to
// recover from a downstream that drifted out of sync (`authd admin sync --target=vault`).
func adminSyncCmd() *cobra.Command {
	var target string
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Backfill a downstream provisioning target from auth's tables",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAdminSync(target)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "Integration name from /portal/admin/integrations, or \"all\"")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

func runAdminSync(target string) error {
	app := cli.App{EnvPrefix: "AUTHD"}
	dbMat, adminMat := app.DB(), app.AdminDB()
	if dbMat.URL == "" {
		return fmt.Errorf("AUTHD_DATABASE_URL is required")
	}
	masterKey, err := bcrypto.ParseKEK(envutil.MustEnv("AUTHD_MASTER_KEY"))
	if err != nil {
		return fmt.Errorf("parse master key: %w", err)
	}

	adminDBTLS, err := dbAdminTLS(adminMat)
	if err != nil {
		return fmt.Errorf("admin db TLS: %w", err)
	}
	dbTLS, err := dbRuntimeTLS(dbMat)
	if err != nil {
		return fmt.Errorf("db TLS: %w", err)
	}
	outboundTLS, err := outboundTLSFromEnv()
	if err != nil {
		return fmt.Errorf("outbound TLS: %w", err)
	}
	if err := postgres.Migrate(adminMat.URL, adminDBTLS); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db, err := postgres.OpenWithTLS(dbMat.URL, dbTLS)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	log, _, drainLog := applog.AppLoggerWithNATS(applog.Config{App: appName}, applog.NATSConfig{
		URL:      os.Getenv("AUTHD_NATS_URL"),
		CertFile: os.Getenv("AUTHD_NATS_CERT"),
		KeyFile:  os.Getenv("AUTHD_NATS_KEY"),
		CAFile:   envutil.First("AUTHD_NATS_CA", "AUTHD_WORKLOAD_CA"),
	}, applog.WithStdout())
	defer drainLog()
	kp := bcrypto.NewLocalKeyProvider(masterKey)
	ctx := context.Background()

	if err := autoImportLegacyVaultEnv(ctx, db, kp, log); err != nil {
		log.Error("auto-import legacy vault env", "err", err)
	}

	var integrations []*model.AppIntegration
	switch target {
	case "":
		return fmt.Errorf("--target is required (use \"all\" or an integration name)")
	case "all":
		integrations, err = db.ListEnabledIntegrations(ctx)
		if err != nil {
			return fmt.Errorf("list integrations: %w", err)
		}
		if len(integrations) == 0 {
			return fmt.Errorf("no enabled integrations to sync")
		}
	default:
		i, err := db.GetIntegrationByName(ctx, target)
		if err != nil {
			return fmt.Errorf("integration %q: %w", target, err)
		}
		integrations = []*model.AppIntegration{i}
	}

	for _, integration := range integrations {
		prov, err := buildProvisioner(ctx, integration, db, kp, outboundTLS, log)
		if err != nil {
			log.Error("build provisioner", "integration", integration.Name, "err", err)
			continue
		}
		userOK, userFail, groupOK, groupFail := syncOneTarget(ctx, db, prov, log)
		fmt.Printf("sync %s done: users %d ok / %d failed; groups %d ok / %d failed\n",
			integration.Name, userOK, userFail, groupOK, groupFail)
	}
	return nil
}

// parseDurationEnv reads key from the environment and parses it as a
// time.Duration. Returns 0 when unset or unparseable so the caller can
// fall back to its own default — keeps env-var validation centralised
// without forcing callers to thread a logger or error path through.
func parseDurationEnv(key string) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0
	}
	return d
}

// runDeviceGrantReaper deletes expired device_grants rows on a fixed
// tick. Cheap query, runs every minute by default; long-lived pending
// or terminal rows just sit in the table until expires_at passes.
// Errors are logged but never propagated — the reaper is best-effort
// housekeeping, not load-bearing for correctness (the /token handler
// also rejects expired rows at read time).
func runDeviceGrantReaper(ctx context.Context, db *postgres.DB, interval time.Duration, log *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			guard.Tick(log, "device-grant-reaper", func() {
				if n, err := db.DeleteExpiredDeviceGrants(ctx); err != nil {
					log.Error("device grant reap", "err", err)
				} else if n > 0 {
					log.Debug("device grant reap", "deleted", n)
				}
			})
		}
	}
}

// provisionSyncInterval returns the parsed AUTHD_PROVISION_SYNC_INTERVAL or the
// default of 1 hour. A zero/negative value disables the background sync.
func provisionSyncInterval(log *slog.Logger) time.Duration {
	v := strings.TrimSpace(os.Getenv("AUTHD_PROVISION_SYNC_INTERVAL"))
	if v == "" {
		return time.Hour
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Warn("AUTHD_PROVISION_SYNC_INTERVAL is not a valid duration; periodic sync disabled",
			"value", v, "err", err)
		return 0
	}
	return d
}

// runPeriodicProvisionSync runs a full sync against every live provisioner on
// the configured interval, exiting when ctx is cancelled. The first tick fires
// after `interval` (not at startup) so a cold restart doesn't pile a sync run
// on top of migrations + token pruning + audit-sink connect.
//
// Each tick reuses the live registry's provisioners — no rebuild — so an
// integration the admin disabled mid-tick is dropped on the next snapshot.
// User/group iteration is the same as `authd admin sync`: idempotent
// PATCH-or-POST per user, full-list PUT per group.
func runPeriodicProvisionSync(ctx context.Context, db *postgres.DB, reg *provision.Registry, interval time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Info("periodic provision sync enabled", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			log.Info("periodic provision sync stopped")
			return
		case <-ticker.C:
			guard.Tick(log, "provision-sync", func() {
				provs := reg.Snapshot()
				if len(provs) == 0 {
					log.Debug("periodic provision sync — no enabled integrations, skipping tick")
					return
				}
				start := time.Now()
				for _, prov := range provs {
					if ctx.Err() != nil {
						return
					}
					userOK, userFail, groupOK, groupFail := syncOneTarget(ctx, db, prov, log)
					log.Info("periodic provision sync — target done",
						"target", prov.Name(),
						"users_ok", userOK, "users_failed", userFail,
						"groups_ok", groupOK, "groups_failed", groupFail)
				}
				log.Info("periodic provision sync — tick done",
					"targets", len(provs), "elapsed", time.Since(start))
			})
		}
	}
}

func syncOneTarget(ctx context.Context, db *postgres.DB, prov provision.Provisioner, log *slog.Logger) (userOK, userFail, groupOK, groupFail int) {
	return provision.SyncAll(ctx, db, prov, log)
}

// awsFedReapInterval returns the parsed AUTHD_AWSFED_REAP_INTERVAL or the
// default of 6 hours. A zero/negative value disables the reaper. The reaper
// trims aws_revoked_users entries past the role's MaxSessionDurationSec —
// 6h is conservative for a typical 1h role lifetime and bounds the inline
// policy growth without thrashing AWS.
func awsFedReapInterval(log *slog.Logger) time.Duration {
	v := strings.TrimSpace(os.Getenv("AUTHD_AWSFED_REAP_INTERVAL"))
	if v == "" {
		return 6 * time.Hour
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Warn("AUTHD_AWSFED_REAP_INTERVAL is not a valid duration; reaper disabled",
			"value", v, "err", err)
		return 0
	}
	return d
}

// runAWSFedReaper periodically prunes expired entries from each federation
// role's AuthRevokedUsers inline policy. Reuses the live provisioner from
// the registry (whichever `aws_federation` integration is enabled) — if no
// such integration is enabled, the reaper exits silently each tick. Walks
// only one provisioner; multiple aws_federation rows are unusual but
// supported (each manages its own roles via the shared aws_roles table).
func runAWSFedReaper(ctx context.Context, reg *provision.Registry, interval time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Info("aws federation revocation reaper enabled", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			log.Info("aws federation revocation reaper stopped")
			return
		case <-ticker.C:
			guard.Tick(log, "awsfed-reaper", func() {
				now := time.Now().UTC()
				for _, prov := range reg.Snapshot() {
					if ctx.Err() != nil {
						return
					}
					fed, ok := prov.(*awsfed.Provisioner)
					if !ok {
						continue
					}
					if err := fed.ReapExpired(ctx, now); err != nil {
						log.Error("aws federation reap", "target", fed.Name(), "err", err)
					}
				}
			})
		}
	}
}

// buildProvSet constructs a provision.Set from every enabled integration row.
// Decryption errors are logged and the offending row is skipped so a single
// corrupt config cannot wedge the whole fan-out.
func buildProvSet(ctx context.Context, db *postgres.DB, kp bcrypto.KeyProvider, outboundTLS *tls.Config, log *slog.Logger) (*provision.Set, error) {
	rows, err := db.ListEnabledIntegrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("list integrations: %w", err)
	}
	set := &provision.Set{Log: log}
	for _, row := range rows {
		prov, err := buildProvisioner(ctx, row, db, kp, outboundTLS, log)
		if err != nil {
			log.Error("build provisioner", "integration", row.Name, "err", err)
			continue
		}
		set.Provisioners = append(set.Provisioners, prov)
	}
	log.Info("provisioner registry loaded", "count", len(set.Provisioners))
	return set, nil
}

func buildProvisioner(ctx context.Context, i *model.AppIntegration, db *postgres.DB, kp bcrypto.KeyProvider, outboundTLS *tls.Config, log *slog.Logger) (provision.Provisioner, error) {
	switch i.Provider {
	case model.AppIntegrationProviderSCIM:
		if i.Config.BaseURL == "" {
			return nil, fmt.Errorf("scim integration %q missing base_url", i.Name)
		}
		authMode := i.Config.AuthMode
		if authMode == "" {
			authMode = model.AppIntegrationAuthBearer
		}
		cfg := scimprov.Config{
			Provider: i.Name,
			Name:     i.Name,
			BaseURL:  i.Config.BaseURL,
			Timeout:  time.Duration(i.Config.TimeoutMS) * time.Millisecond,
			Store:    db,
			Log:      log,
		}
		switch authMode {
		case model.AppIntegrationAuthBearer:
			if len(i.EncryptedToken) == 0 || len(i.EncryptedDEK) == 0 {
				return nil, fmt.Errorf("scim integration %q (bearer mode) missing token", i.Name)
			}
			token, err := bcrypto.DecryptEnvelope(ctx, kp, i.EncryptedDEK, i.EncryptedToken)
			if err != nil {
				return nil, fmt.Errorf("decrypt token: %w", err)
			}
			cfg.Token = string(token)
		case model.AppIntegrationAuthMTLS:
			if outboundTLS == nil {
				return nil, fmt.Errorf("scim integration %q uses mtls but AUTHD_SCIM_MTLS_CERT/KEY are unset", i.Name)
			}
			cfg.TLSConfig = outboundTLS
		default:
			return nil, fmt.Errorf("scim integration %q unsupported auth_mode %q", i.Name, authMode)
		}
		return scimprov.New(cfg), nil
	case model.AppIntegrationProviderIAM:
		return iam.New(ctx, i.Name, i.Config.GroupMap, log)
	case model.AppIntegrationProviderAWSFederation:
		// Federation provisioner only does session-revocation on
		// OpDeactivate/OpDelete. Role catalog itself lives in the
		// aws_* tables; this integration row exists primarily as a
		// toggle so admins can disable the revocation push without
		// dropping the catalog.
		return awsfed.New(ctx, i.Name, db, log)
	default:
		return nil, fmt.Errorf("unknown provider %q", i.Provider)
	}
}

// autoImportLegacyVaultEnv seeds an integration row from AUTHD_VAULT_SCIM_*
// env vars on the very first boot after the 007 migration. Subsequent boots
// (table non-empty) ignore the env vars entirely. This preserves rows in the
// external_ids cache by reusing the legacy provider name "vault".
func autoImportLegacyVaultEnv(ctx context.Context, db *postgres.DB, kp bcrypto.KeyProvider, log *slog.Logger) error {
	if !strings.EqualFold(os.Getenv("AUTHD_VAULT_SCIM_ENABLED"), "true") {
		return nil
	}
	existing, err := db.ListIntegrations(ctx)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil // table already populated; env vars deprecated.
	}
	baseURL := os.Getenv("AUTHD_VAULT_SCIM_URL")
	token := os.Getenv("AUTHD_VAULT_SCIM_TOKEN")
	if baseURL == "" || token == "" {
		log.Warn("AUTHD_VAULT_SCIM_ENABLED=true but URL/token missing; skipping auto-import")
		return nil
	}
	encToken, encDEK, err := bcrypto.EncryptEnvelope(ctx, kp, []byte(token))
	if err != nil {
		return fmt.Errorf("encrypt token: %w", err)
	}
	timeout, _ := time.ParseDuration(os.Getenv("AUTHD_VAULT_SCIM_TIMEOUT"))
	row := &model.AppIntegration{
		Name:     scimprov.ProviderName, // "vault" — keeps external_ids rows valid
		Provider: model.AppIntegrationProviderSCIM,
		Enabled:  true,
		Config: model.AppIntegrationConfig{
			BaseURL:   baseURL,
			TimeoutMS: int(timeout / time.Millisecond),
			AuthMode:  model.AppIntegrationAuthBearer,
		},
		EncryptedToken: encToken,
		EncryptedDEK:   encDEK,
	}
	if err := db.CreateIntegration(ctx, row); err != nil {
		return err
	}
	log.Warn("auto-imported AUTHD_VAULT_SCIM_* into app_integrations; env vars are deprecated, manage via /portal/admin/integrations",
		"integration", row.Name)
	return nil
}

func adminUserCmd() *cobra.Command {
	userCmd := &cobra.Command{
		Use:   "user",
		Short: "User management",
	}
	userCmd.AddCommand(adminUserCreateCmd())
	return userCmd
}

func adminUserCreateCmd() *cobra.Command {
	var email, password, name string
	var isAdmin, allowWeak bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a user",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAdminUserCreate(email, password, name, isAdmin, allowWeak)
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "User email (required)")
	cmd.Flags().StringVar(&password, "password", "", "User password (required)")
	cmd.Flags().StringVar(&name, "name", "", "User display name")
	cmd.Flags().BoolVar(&isAdmin, "admin", false, "Grant portal admin role")
	cmd.Flags().BoolVar(&allowWeak, "allow-weak-password", false,
		"Skip PCI password-policy validation. Use only for dev bootstrap; production accounts MUST meet policy.")
	_ = cmd.MarkFlagRequired("email")
	_ = cmd.MarkFlagRequired("password")
	return cmd
}

// validateNewUserPassword runs the default PCI rule set against pw and
// returns a non-nil error when any rule fails. Extracted from
// runAdminUserCreate so unit tests can exercise the gate without
// spinning up a database; runAdminUserCreate calls this directly and
// surfaces the error to the operator's terminal.
//
// allowWeak short-circuits the check — kept as a flag because the CLI
// is sometimes used during cold-start bootstrap of a dev environment
// where the operator wants to set an obviously-weak password
// (e.g. "password") on a throwaway account. Using it on a real
// environment is operator error; the CLI logs a warning when invoked
// with the flag set.
func validateNewUserPassword(pw string, allowWeak bool) error {
	if allowWeak {
		return nil
	}
	// Empty is rejected here, not by the rule engine — PasswordComplexityRule
	// deliberately treats empty Password as "not a credential-check context"
	// so the same engine can be reused in session-state evaluations where
	// only User/Request are populated. New-password validation has to do
	// the non-empty check itself; the portal form handlers follow the
	// same pattern.
	if pw == "" {
		return fmt.Errorf("password cannot be empty (pass --allow-weak-password to override; not for production)")
	}
	eng := policy.New(policy.DefaultPCIRules()...)
	if v := eng.First(policy.PolicyContext{Password: pw}); v != nil {
		return fmt.Errorf("password policy violation: %s (pass --allow-weak-password to override; not for production)", v.Message)
	}
	return nil
}

func runAdminUserCreate(email, password, name string, isAdmin, allowWeak bool) error {
	if err := validateNewUserPassword(password, allowWeak); err != nil {
		return err
	}
	app := cli.App{EnvPrefix: "AUTHD"}
	dbMat, adminMat := app.DB(), app.AdminDB()
	if dbMat.URL == "" {
		return fmt.Errorf("AUTHD_DATABASE_URL is required")
	}

	adminDBTLS, err := dbAdminTLS(adminMat)
	if err != nil {
		return fmt.Errorf("admin db TLS: %w", err)
	}
	dbTLS, err := dbRuntimeTLS(dbMat)
	if err != nil {
		return fmt.Errorf("db TLS: %w", err)
	}
	if err := postgres.Migrate(adminMat.URL, adminDBTLS); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db, err := postgres.OpenWithTLS(dbMat.URL, dbTLS)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	if allowWeak {
		// Loud warning so the operator notices in their shell history.
		// Not fatal — they asked for this — but conspicuous enough that
		// a CI pipeline using --allow-weak-password by accident shows
		// up in build logs.
		fmt.Fprintln(os.Stderr, "WARNING: --allow-weak-password set; password policy was NOT enforced for this user.")
	}

	hash, err := creds.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if name == "" {
		name = strings.SplitN(email, "@", 2)[0]
	}
	ctx := context.Background()
	user, err := db.CreateUser(ctx, strings.ToLower(email), hash, name)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	if isAdmin {
		if err := db.SetUserAdmin(ctx, user.ID, true); err != nil {
			return fmt.Errorf("set admin: %w", err)
		}
	}
	fmt.Printf("created user %s (id: %s, admin: %v)\n", user.Email, user.ID, isAdmin)
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// outboundTLSFromEnv builds the *tls.Config used by mTLS-mode integrations to
// authenticate auth as a client to downstream SCIM endpoints. A single shared
// cert/key pair is presented for every mtls integration (auth has one IdP
// identity). Returns nil when no env vars are set; mtls-mode integrations then
// fail at registry-build time with a clear error.
//
// A full cert+key pair gets reloader.ClientConfig — the presented client cert
// is re-read per handshake and the CA pool on mtime — so a cert-agentd
// rotation lands without a restart. Anything short of a pair falls back to
// one-shot btls.FromFiles (CA-only server-auth verification, or nil when
// nothing is configured).
//
//	AUTHD_SCIM_MTLS_CERT  Client cert PEM path.
//	AUTHD_SCIM_MTLS_KEY   Client key PEM path. Required iff CERT is set.
//	AUTHD_SCIM_MTLS_CA    Optional CA bundle for verifying downstream servers.
//	                     Falls back to AUTHD_WORKLOAD_CA, then to the system
//	                     root pool.
func outboundTLSFromEnv() (*tls.Config, error) {
	certFile := os.Getenv("AUTHD_SCIM_MTLS_CERT")
	keyFile := os.Getenv("AUTHD_SCIM_MTLS_KEY")
	caFile := envutil.First("AUTHD_SCIM_MTLS_CA", "AUTHD_WORKLOAD_CA")
	if certFile != "" && keyFile != "" {
		return reloader.ClientConfig(certFile, keyFile, caFile)
	}
	return btls.FromFiles(certFile, keyFile, caFile)
}

// dbAdminTLS builds the one-shot admin (migration) TLS config from resolved
// AdminDB material (cert/key: AUTHD_ADMIN_DB_* → AUTHD_DB_*; CA additionally →
// AUTHD_WORKLOAD_CA — see cli.App.AdminDB). admin always uses FromFiles — the
// migrate connection is short-lived and closed before any rotation matters.
func dbAdminTLS(m cli.DB) (*tls.Config, error) {
	return btls.FromFiles(m.CertFile, m.KeyFile, m.CAFile)
}

// dbRuntimeTLS builds the runtime Postgres TLS config from resolved DB
// material — cert/key from AUTHD_DB_CERT/KEY (a DB-role credential, no
// WORKLOAD fallback), CA from AUTHD_DB_CA → AUTHD_WORKLOAD_CA. A full cert+key
// pair gets reloader.ClientConfig — leaf re-read per handshake, CA pool on
// mtime — so a cert-agentd rotation lands on the next pool dial
// (within SetConnMaxLifetime) without a restart and without a poll loop.
// Anything short of a pair falls back to one-shot btls.FromFiles (CA-only
// server-auth or plaintext, as the DSN's sslmode dictates).
func dbRuntimeTLS(m cli.DB) (*tls.Config, error) {
	if m.CertFile != "" && m.KeyFile != "" {
		return reloader.ClientConfig(m.CertFile, m.KeyFile, m.CAFile)
	}
	return btls.FromFiles(m.CertFile, m.KeyFile, m.CAFile)
}

// buildServerTLS constructs the server tls.Config.
// Cert source priority:
//  1. AUTHD_API_CERT + AUTHD_API_KEY files (hot-reload via GetCertificate)
//  2. Auto-generated self-signed cert (dev fallback, logs a warning)
//
// If AUTHD_API_CLIENT_CA is set, mTLS client verification is enabled.
func buildServerTLS(log *slog.Logger) (*tls.Config, error) {
	certFile := os.Getenv("AUTHD_API_CERT")
	keyFile := os.Getenv("AUTHD_API_KEY")
	clientCAFile := os.Getenv("AUTHD_API_CLIENT_CA")

	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("AUTHD_API_CERT and AUTHD_API_KEY must both be set or both unset")
	}

	cfg := &tls.Config{}
	if certFile != "" {
		log.Info("TLS: using certificate files (hot-reload enabled)", "cert", certFile)
		loader := reloader.NewCertLoader(certFile, keyFile)
		cfg.GetCertificate = loader.GetCertificate
	} else {
		log.Warn("TLS: no certificate configured, using self-signed (not for production)")
		cert, err := btls.SelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if clientCAFile != "" {
		// Hot-reload the inbound client-CA bundle: base wires ClientAuth +
		// ClientCAs + a per-handshake GetConfigForClient so a CA rotation
		// (widen→narrow) lands without a restart, keeping the last good pool
		// on a bad drop-in.
		caLoader, err := reloader.NewClientCALoader(cfg, clientCAFile, tls.VerifyClientCertIfGiven)
		if err != nil {
			return nil, fmt.Errorf("AUTHD_API_CLIENT_CA: %w", err)
		}
		caLoader.OnError = func(err error) {
			log.Warn("TLS: client CA hot-reload kept previous pool", "ca", clientCAFile, "err", err)
		}
		log.Info("TLS: mTLS client CA loaded (hot-reload)", "ca", clientCAFile)
	}

	return cfg, nil
}

func webAuthnParams(issuer string) (rpID string, origins []string) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "localhost", []string{issuer}
	}
	// Strip port for RPID; origins include the full scheme+host.
	host := u.Hostname()
	if override := os.Getenv("AUTHD_WEBAUTHN_RPID"); override != "" {
		host = override
	}
	origin := u.Scheme + "://" + u.Host
	extraOrigins := strings.Fields(os.Getenv("AUTHD_WEBAUTHN_ORIGINS"))
	origins = append([]string{origin}, extraOrigins...)
	return host, origins
}
