// Command authd is the tokyo3-auth Identity Provider server.
//
// Required env vars:
//
//	AUTH_MASTER_KEY       64-char hex master key (run `authd keygen`).
//	AUTH_ISSUER           Public issuer URL — used in OIDC discovery and JWT iss claim.
//	AUTH_DATABASE_URL     Runtime Postgres DSN (DML-only role).
//
// Optional:
//
//	AUTH_ADMIN_DATABASE_URL  Admin DSN used for schema migrations (DDL).
//	                         Falls back to AUTH_DATABASE_URL when unset.
//	AUTH_PORT                HTTPS listen port (default: 8443).
//	AUTH_ALLOW_REGISTRATION  Set to "true" to enable self-registration at /register.
//
// TLS — the API always serves HTTPS (IdP requirement):
//
//	AUTH_TLS_CERT         Path to server TLS certificate PEM (hot-reloaded;
//	                      the file's mtime is polled at most once per second
//	                      across handshakes, so rotations land within ~1s).
//	AUTH_TLS_KEY          Path to server TLS private key PEM. Must be paired with AUTH_TLS_CERT.
//	                      If neither is set, an ephemeral self-signed cert is generated (dev only).
//	AUTH_TLS_CLIENT_CA    Optional CA PEM for client cert verification (mTLS).
//
// Database mTLS (optional, used together with cert-auth Postgres):
//
//	AUTH_DB_CERT          Client certificate PEM for the runtime auth→postgres connection.
//	AUTH_DB_KEY           Client key PEM (must be paired with AUTH_DB_CERT).
//	AUTH_DB_CA            CA PEM for verifying the postgres server certificate.
//	AUTH_ADMIN_DB_CERT    Client certificate PEM for the admin (migration) connection.
//	AUTH_ADMIN_DB_KEY     Client key PEM.
//	AUTH_ADMIN_DB_CA      CA PEM.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/abagile/tokyo3-auth/internal/api"
	"github.com/abagile/tokyo3-auth/internal/auth"
	"github.com/abagile/tokyo3-auth/internal/crypto"
	internaljwt "github.com/abagile/tokyo3-auth/internal/jwt"
	"github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/policy"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/provision/iam"
	scimprov "github.com/abagile/tokyo3-auth/internal/provision/scim"
	"github.com/abagile/tokyo3-auth/internal/store/postgres"
	"github.com/abagile/tokyo3-auth/internal/tlsutil"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

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
	root.AddCommand(serveCmd(), migrateCmd(), keygenCmd(), adminCmd())
	return root
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
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	issuer := mustEnv("AUTH_ISSUER")
	dbURL := mustEnv("AUTH_DATABASE_URL")
	adminDBURL := envOr("AUTH_ADMIN_DATABASE_URL", dbURL)
	masterKeyHex := mustEnv("AUTH_MASTER_KEY")
	port := envOr("AUTH_PORT", "8443")

	masterKey, err := crypto.ParseKEK(masterKeyHex)
	if err != nil {
		return fmt.Errorf("parse master key: %w", err)
	}

	adminDBTLS, dbTLS, err := dbTLSFromEnv()
	if err != nil {
		return err
	}

	// Run migrations with the admin DSN, then open the runtime connection.
	if adminDBTLS != nil {
		log.Info("running migrations (mTLS)")
	} else {
		log.Info("running migrations")
	}
	if err := postgres.Migrate(adminDBURL, adminDBTLS); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db, err := postgres.OpenWithTLS(dbURL, dbTLS)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	kp := crypto.NewLocalKeyProvider(masterKey)

	signer, err := internaljwt.LoadOrCreate(ctx, db, kp, issuer)
	if err != nil {
		return fmt.Errorf("jwt signer: %w", err)
	}

	// Derive WebAuthn RPID from issuer URL.
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
		return buildProvSet(ctx, db, kp, log)
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
		Issuer:            issuer,
		MasterKey:         masterKey,
		Log:               log,
		AllowRegistration: strings.EqualFold(os.Getenv("AUTH_ALLOW_REGISTRATION"), "true"),
	})
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	tlsCfg, err := buildServerTLS(log)
	if err != nil {
		return fmt.Errorf("server TLS: %w", err)
	}

	addr := ":" + port
	httpSrv := &http.Server{
		Addr:      addr,
		Handler:   srv.Routes(),
		TLSConfig: tlsCfg,
	}

	log.Info("starting server", "addr", addr, "issuer", issuer, "tls", true)
	go func() {
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
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
			dbURL := mustEnv("AUTH_ADMIN_DATABASE_URL")
			adminDBTLS, err := tlsutil.FromFiles(
				os.Getenv("AUTH_ADMIN_DB_CERT"),
				os.Getenv("AUTH_ADMIN_DB_KEY"),
				os.Getenv("AUTH_ADMIN_DB_CA"),
			)
			if err != nil {
				return fmt.Errorf("admin db TLS: %w", err)
			}
			if err := postgres.Migrate(dbURL, adminDBTLS); err != nil {
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
			key, err := crypto.GenerateKEK()
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
	dbURL := mustEnv("AUTH_DATABASE_URL")
	adminDBURL := envOr("AUTH_ADMIN_DATABASE_URL", dbURL)
	masterKey, err := crypto.ParseKEK(mustEnv("AUTH_MASTER_KEY"))
	if err != nil {
		return fmt.Errorf("parse master key: %w", err)
	}

	adminDBTLS, dbTLS, err := dbTLSFromEnv()
	if err != nil {
		return err
	}
	if err := postgres.Migrate(adminDBURL, adminDBTLS); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db, err := postgres.OpenWithTLS(dbURL, dbTLS)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	kp := crypto.NewLocalKeyProvider(masterKey)
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
		prov, err := buildProvisioner(ctx, integration, db, kp, log)
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

func syncOneTarget(ctx context.Context, db *postgres.DB, prov provision.Provisioner, log *slog.Logger) (userOK, userFail, groupOK, groupFail int) {
	users, err := db.ListUsers(ctx)
	if err != nil {
		log.Error("list users", "err", err)
		return
	}
	usersByID := make(map[uuid.UUID]*model.User, len(users))
	for _, u := range users {
		usersByID[u.ID] = u
		if err := prov.User(ctx, provision.OpCreate, u, nil); err != nil {
			log.Error("sync user", "target", prov.Name(), "email", u.Email, "err", err)
			userFail++
			continue
		}
		userOK++
	}
	groups, err := db.ListGroups(ctx)
	if err != nil {
		log.Error("list groups", "err", err)
		return
	}
	for _, g := range groups {
		members := make([]*model.User, 0, len(g.Members))
		for _, mid := range g.Members {
			if m, ok := usersByID[mid]; ok {
				members = append(members, m)
			}
		}
		if err := prov.Group(ctx, provision.OpCreate, g, members); err != nil {
			log.Error("sync group", "target", prov.Name(), "displayName", g.DisplayName, "err", err)
			groupFail++
			continue
		}
		groupOK++
	}
	return
}

// buildProvSet constructs a provision.Set from every enabled integration row.
// Decryption errors are logged and the offending row is skipped so a single
// corrupt config cannot wedge the whole fan-out.
func buildProvSet(ctx context.Context, db *postgres.DB, kp crypto.KeyProvider, log *slog.Logger) (*provision.Set, error) {
	rows, err := db.ListEnabledIntegrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("list integrations: %w", err)
	}
	set := &provision.Set{Log: log}
	for _, row := range rows {
		prov, err := buildProvisioner(ctx, row, db, kp, log)
		if err != nil {
			log.Error("build provisioner", "integration", row.Name, "err", err)
			continue
		}
		set.Provisioners = append(set.Provisioners, prov)
	}
	log.Info("provisioner registry loaded", "count", len(set.Provisioners))
	return set, nil
}

func buildProvisioner(ctx context.Context, i *model.AppIntegration, db *postgres.DB, kp crypto.KeyProvider, log *slog.Logger) (provision.Provisioner, error) {
	switch i.Provider {
	case model.AppIntegrationProviderSCIM:
		if i.Config.BaseURL == "" {
			return nil, fmt.Errorf("scim integration %q missing base_url", i.Name)
		}
		if len(i.EncryptedToken) == 0 || len(i.EncryptedDEK) == 0 {
			return nil, fmt.Errorf("scim integration %q missing token", i.Name)
		}
		token, err := crypto.DecryptSecret(ctx, kp, i.EncryptedDEK, i.EncryptedToken)
		if err != nil {
			return nil, fmt.Errorf("decrypt token: %w", err)
		}
		return scimprov.New(scimprov.Config{
			Provider: i.Name,
			Name:     i.Name,
			BaseURL:  i.Config.BaseURL,
			Token:    string(token),
			Timeout:  time.Duration(i.Config.TimeoutMS) * time.Millisecond,
			Store:    db,
			Log:      log,
		}), nil
	case model.AppIntegrationProviderIAM:
		return iam.New(ctx, i.Name, i.Config.GroupMap, log)
	default:
		return nil, fmt.Errorf("unknown provider %q", i.Provider)
	}
}

// autoImportLegacyVaultEnv seeds an integration row from AUTH_VAULT_SCIM_*
// env vars on the very first boot after the 007 migration. Subsequent boots
// (table non-empty) ignore the env vars entirely. This preserves rows in the
// external_ids cache by reusing the legacy provider name "vault".
func autoImportLegacyVaultEnv(ctx context.Context, db *postgres.DB, kp crypto.KeyProvider, log *slog.Logger) error {
	if !strings.EqualFold(os.Getenv("AUTH_VAULT_SCIM_ENABLED"), "true") {
		return nil
	}
	existing, err := db.ListIntegrations(ctx)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil // table already populated; env vars deprecated.
	}
	baseURL := os.Getenv("AUTH_VAULT_SCIM_URL")
	token := os.Getenv("AUTH_VAULT_SCIM_TOKEN")
	if baseURL == "" || token == "" {
		log.Warn("AUTH_VAULT_SCIM_ENABLED=true but URL/token missing; skipping auto-import")
		return nil
	}
	encToken, encDEK, err := crypto.EncryptSecret(ctx, kp, []byte(token))
	if err != nil {
		return fmt.Errorf("encrypt token: %w", err)
	}
	timeout, _ := time.ParseDuration(os.Getenv("AUTH_VAULT_SCIM_TIMEOUT"))
	row := &model.AppIntegration{
		Name:     scimprov.ProviderName, // "vault" — keeps external_ids rows valid
		Provider: model.AppIntegrationProviderSCIM,
		Enabled:  true,
		Config: model.AppIntegrationConfig{
			BaseURL:   baseURL,
			TimeoutMS: int(timeout / time.Millisecond),
		},
		EncryptedToken: encToken,
		EncryptedDEK:   encDEK,
	}
	if err := db.CreateIntegration(ctx, row); err != nil {
		return err
	}
	log.Warn("auto-imported AUTH_VAULT_SCIM_* into app_integrations; env vars are deprecated, manage via /portal/admin/integrations",
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
	var isAdmin bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a user",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAdminUserCreate(email, password, name, isAdmin)
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "User email (required)")
	cmd.Flags().StringVar(&password, "password", "", "User password (required)")
	cmd.Flags().StringVar(&name, "name", "", "User display name")
	cmd.Flags().BoolVar(&isAdmin, "admin", false, "Grant portal admin role")
	_ = cmd.MarkFlagRequired("email")
	_ = cmd.MarkFlagRequired("password")
	return cmd
}

func runAdminUserCreate(email, password, name string, isAdmin bool) error {
	dbURL := mustEnv("AUTH_DATABASE_URL")
	adminDBURL := envOr("AUTH_ADMIN_DATABASE_URL", dbURL)

	adminDBTLS, dbTLS, err := dbTLSFromEnv()
	if err != nil {
		return err
	}
	if err := postgres.Migrate(adminDBURL, adminDBTLS); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db, err := postgres.OpenWithTLS(dbURL, dbTLS)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	hash, err := auth.HashPassword(password)
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

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "error: %s environment variable is required\n", key)
		os.Exit(1)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// dbTLSFromEnv builds the (admin, runtime) DB TLS configs from the AUTH_*_DB_*
// env vars. Either may be nil when the corresponding cert vars are unset, in
// which case the connection falls back to plain TLS / non-TLS as the DSN's
// sslmode dictates.
func dbTLSFromEnv() (admin, runtime *tls.Config, err error) {
	admin, err = tlsutil.FromFiles(
		os.Getenv("AUTH_ADMIN_DB_CERT"),
		os.Getenv("AUTH_ADMIN_DB_KEY"),
		os.Getenv("AUTH_ADMIN_DB_CA"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("admin db TLS: %w", err)
	}
	runtime, err = tlsutil.FromFiles(
		os.Getenv("AUTH_DB_CERT"),
		os.Getenv("AUTH_DB_KEY"),
		os.Getenv("AUTH_DB_CA"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("db TLS: %w", err)
	}
	return admin, runtime, nil
}

// buildServerTLS constructs the server tls.Config.
// Cert source priority:
//  1. AUTH_TLS_CERT + AUTH_TLS_KEY files (hot-reload via GetCertificate)
//  2. Auto-generated self-signed cert (dev fallback, logs a warning)
//
// If AUTH_TLS_CLIENT_CA is set, mTLS client verification is enabled.
func buildServerTLS(log *slog.Logger) (*tls.Config, error) {
	certFile := os.Getenv("AUTH_TLS_CERT")
	keyFile := os.Getenv("AUTH_TLS_KEY")
	clientCAFile := os.Getenv("AUTH_TLS_CLIENT_CA")

	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("AUTH_TLS_CERT and AUTH_TLS_KEY must both be set or both unset")
	}

	cfg := &tls.Config{}
	if certFile != "" {
		log.Info("TLS: using certificate files (hot-reload enabled)", "cert", certFile)
		loader := tlsutil.NewCertLoader(certFile, keyFile)
		cfg.GetCertificate = loader.GetCertificate
	} else {
		log.Warn("TLS: no certificate configured, using self-signed (not for production)")
		cert, err := tlsutil.SelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if clientCAFile != "" {
		data, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read AUTH_TLS_CLIENT_CA: %w", err)
		}
		pool, err := tlsutil.CertPoolFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parse AUTH_TLS_CLIENT_CA: %w", err)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		log.Info("TLS: mTLS client CA loaded", "ca", clientCAFile)
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
	origin := u.Scheme + "://" + u.Host
	extraOrigins := strings.Fields(os.Getenv("AUTH_WEBAUTHN_ORIGINS"))
	origins = append([]string{origin}, extraOrigins...)
	return host, origins
}
