// Command authd is the tokyo3-auth Identity Provider server.
package main

import (
	"context"
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
	iaws "github.com/abagile/tokyo3-auth/internal/aws"
	"github.com/abagile/tokyo3-auth/internal/crypto"
	internaljwt "github.com/abagile/tokyo3-auth/internal/jwt"
	"github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/policy"
	"github.com/abagile/tokyo3-auth/internal/store/postgres"
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
	port := envOr("AUTH_PORT", "8080")

	masterKey, err := crypto.ParseKEK(masterKeyHex)
	if err != nil {
		return fmt.Errorf("parse master key: %w", err)
	}

	// Run migrations with the admin DSN, then open the runtime connection.
	log.Info("running migrations")
	if err := postgres.Migrate(adminDBURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db, err := postgres.Open(dbURL)
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

	var iamProv *iaws.IAMProvisioner
	if strings.EqualFold(os.Getenv("AUTH_AWS_IAM_ENABLED"), "true") {
		iamProv, err = iaws.NewIAMProvisioner(ctx, nil, log)
		if err != nil {
			log.Error("iam provisioner init", "err", err)
			// Non-fatal: continue without IAM provisioning.
		}
	}

	srv, err := api.New(api.Config{
		Store:             db,
		Signer:            signer,
		Policy:            eng,
		WAHandler:         waHandler,
		KP:                kp,
		IAM:               iamProv,
		Issuer:            issuer,
		MasterKey:         masterKey,
		Log:               log,
		AllowRegistration: strings.EqualFold(os.Getenv("AUTH_ALLOW_REGISTRATION"), "true"),
	})
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	addr := ":" + port
	httpSrv := &http.Server{
		Addr:    addr,
		Handler: srv.Routes(),
	}

	log.Info("starting server", "addr", addr, "issuer", issuer)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
			if err := postgres.Migrate(dbURL); err != nil {
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
	admin.AddCommand(adminUserCmd())
	return admin
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

	if err := postgres.Migrate(adminDBURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db, err := postgres.Open(dbURL)
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
