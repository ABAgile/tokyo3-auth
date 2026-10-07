package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/abagile/tokyo3-auth/internal/store/storetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Compile-time assertion: *DB satisfies the full store.Store contract.
var _ store.Store = (*DB)(nil)

// testDSNEnvs are consulted in order for a DSN of a PostgreSQL server the
// tests may create databases on. The first is test-specific; the others are
// authd's own (admin DSN, which falls back to the runtime DSN), so a
// developer environment that already points authd at Postgres gets these
// tests automatically. A `sqlite:` value or an unset variable is skipped.
//
// Each test gets its own throwaway authtest_* database (created, migrated,
// then dropped on cleanup), so existing data is never touched; the role needs
// CREATEDB. No usable DSN ⇒ tests needing a server are skipped.
var testDSNEnvs = []string{"AUTHD_TEST_POSTGRES_URL", "AUTHD_ADMIN_DATABASE_URL", "AUTHD_DATABASE_URL"}

// testAdminDSN returns the first configured Postgres DSN and its source env.
func testAdminDSN() (dsn, env string) {
	for _, k := range testDSNEnvs {
		v := strings.TrimSpace(os.Getenv(k))
		if v != "" && !strings.HasPrefix(v, "sqlite:") {
			return v, k
		}
	}
	return "", ""
}

// dsnForDatabase returns dsn pointed at database name, for both URL
// (postgres://…) and keyword/value (host=… dbname=…) forms.
func dsnForDatabase(dsn, name string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", err
		}
		u.Path = "/" + name
		return u.String(), nil
	}
	return dsn + " dbname=" + name, nil // last keyword wins
}

// newTestDB creates a fresh uniquely named database, migrates it, and returns
// a store on it plus its DSN. The database is dropped when t finishes.
func newTestDB(t *testing.T) (*DB, string) {
	t.Helper()
	adminDSN, env := testAdminDSN()
	if adminDSN == "" {
		t.Skipf("none of %s set; skipping PostgreSQL tests", strings.Join(testDSNEnvs, ", "))
	}

	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatal(err)
	}
	name := "authtest_" + hex.EncodeToString(rnd[:])

	admin, err := openWithTLS(adminDSN, nil)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	t.Cleanup(func() { admin.Close() })
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		var pgErr *pgconn.PgError
		if env != "AUTHD_TEST_POSTGRES_URL" && errors.As(err, &pgErr) && pgErr.Code == "42501" {
			// Picked up from authd's own (possibly DML-only) role: not a
			// test failure, just no way to make a scratch database.
			t.Skipf("%s role cannot CREATE DATABASE; set AUTHD_TEST_POSTGRES_URL to a role that can", env)
		}
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		// FORCE terminates any connection a failed test left open.
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`); err != nil {
			t.Errorf("drop database %s: %v", name, err)
		}
	})

	dsn, err := dsnForDatabase(adminDSN, name)
	if err != nil {
		t.Fatalf("build dsn: %v", err)
	}
	if err := Migrate(dsn, nil); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	db, err := OpenWithTLS(dsn, nil)
	if err != nil {
		t.Fatalf("OpenWithTLS: %v", err)
	}
	// Registered after the drop cleanup, so it runs first (LIFO).
	t.Cleanup(func() { db.Close() })
	return db, dsn
}

// TestStoreContract runs the shared behavioural contract (also run against
// SQLite) on a real PostgreSQL database.
func TestStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		db, _ := newTestDB(t)
		return db
	})
}

func embeddedMigrations(t *testing.T) []string {
	t.Helper()
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	return names
}

// TestMigrationsApply: every embedded migration is applied and recorded on a
// fresh database, and re-running Migrate is a no-op.
func TestMigrationsApply(t *testing.T) {
	_, dsn := newTestDB(t)
	want := embeddedMigrations(t)

	applied := func() []string {
		t.Helper()
		raw, err := openWithTLS(dsn, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		rows, err := raw.Query(`SELECT version FROM schema_migrations ORDER BY version`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var got []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			got = append(got, v)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := applied(); !reflect.DeepEqual(got, want) {
		t.Fatalf("applied migrations = %v, want %v", got, want)
	}
	if err := Migrate(dsn, nil); err != nil {
		t.Fatalf("re-run Migrate: %v", err)
	}
	if got := applied(); !reflect.DeepEqual(got, want) {
		t.Errorf("after re-run, applied = %v, want %v", got, want)
	}
}

// TestMigrationFailureRollsBack: a failing migration leaves no partial schema
// and no schema_migrations row (each runs in its own transaction).
func TestMigrationFailureRollsBack(t *testing.T) {
	db, _ := newTestDB(t)
	tx, err := db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`CREATE TABLE half_applied (id int); SELECT * FROM does_not_exist`); err == nil {
		t.Fatal("expected migration SQL to fail")
	}
	_ = tx.Rollback()
	var n int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'half_applied'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("partial schema leaked: n=%d err=%v", n, err)
	}
}

// TestMigrationDisablesOnlyRetiredIAMIntegrations mirrors the upgrade from
// 019: migration 020 disables legacy aws_iam integrations without deleting
// them or touching their config, and leaves other providers alone.
func TestMigrationDisablesOnlyRetiredIAMIntegrations(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	rows := []*model.AppIntegration{
		{ID: uuid.New(), Name: "legacy-enabled", Provider: "aws_iam", Enabled: true},
		{ID: uuid.New(), Name: "legacy-disabled", Provider: "aws_iam", Enabled: false},
		{ID: uuid.New(), Name: "scim", Provider: model.AppIntegrationProviderSCIM, Enabled: true},
		{ID: uuid.New(), Name: "federation", Provider: model.AppIntegrationProviderAWSFederation, Enabled: true},
	}
	for _, row := range rows {
		if err := db.CreateIntegration(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	const legacyConfig = `{"group_map":{"Engineering":"legacy-iam-group"}}`
	if _, err := db.db.Exec(`UPDATE app_integrations SET config = $1 WHERE id = $2`, legacyConfig, rows[0].ID); err != nil {
		t.Fatal(err)
	}
	// Removing the marker restores the pre-020 state (it originally ran
	// against an empty table).
	if _, err := db.db.Exec(`DELETE FROM schema_migrations WHERE version = '020_disable_aws_iam.sql'`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := db.migrate(); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			got, err := db.GetIntegration(ctx, row.ID)
			if err != nil {
				t.Fatalf("migration deleted %q: %v", row.Name, err)
			}
			if wantEnabled := row.Provider != "aws_iam"; got.Enabled != wantEnabled || got.Provider != row.Provider {
				t.Errorf("migration changed the wrong fields: %+v", got)
			}
		}
		var config string
		if err := db.db.QueryRow(`SELECT config::text FROM app_integrations WHERE id = $1`, rows[0].ID).Scan(&config); err != nil {
			t.Fatal(err)
		}
		if strings.ReplaceAll(config, " ", "") != legacyConfig {
			t.Errorf("legacy config was not retained: %q", config)
		}
		enabled, err := db.ListEnabledIntegrations(ctx)
		if err != nil || len(enabled) != 2 {
			t.Fatalf("enabled integrations = %v, error = %v; want only SCIM and federation", enabled, err)
		}
	}
}

// TestStringArrayEncoding: TEXT[] literals survive awkward element values.
func TestStringArrayEncoding(t *testing.T) {
	cases := [][]string{
		{},
		{"a"},
		{"a", "b,c", `d"e`, `f\g`, "h i", "{j}", ""},
		{"https://app.example/cb?x=1,2&y=\"z\""},
		{"ünïcode", "日本語"},
	}
	for _, in := range cases {
		v, err := stringArray(in).Value()
		if err != nil {
			t.Fatalf("Value(%q): %v", in, err)
		}
		var out stringArray
		if err := out.Scan(v); err != nil {
			t.Fatalf("Scan(%v): %v", v, err)
		}
		if len(in) == 0 && len(out) == 0 {
			continue
		}
		if !reflect.DeepEqual([]string(out), in) {
			t.Errorf("round trip %q -> %v -> %q", in, v, []string(out))
		}
	}
	var nilArr stringArray
	if err := nilArr.Scan(nil); err != nil || nilArr != nil {
		t.Errorf("Scan(nil) = %v, %v", nilArr, err)
	}
	if err := nilArr.Scan(42); err == nil {
		t.Error("Scan(int) should fail")
	}
	if err := nilArr.Scan("not an array"); err == nil {
		t.Error("Scan(malformed) should fail")
	}
}

// TestStringArrayThroughDatabase: awkward values also round trip through a
// real TEXT[] column (client redirect URIs and scopes).
func TestStringArrayThroughDatabase(t *testing.T) {
	db, _ := newTestDB(t)
	ctx := context.Background()
	uris := []string{`https://a.example/cb?x=1,2`, `https://b.example/"quoted"`, `https://c.example/back\slash`}
	scopes := []string{"openid", "a b"}
	c, err := db.CreateClient(ctx, "arr-client", "", "Arr", uris, scopes, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.GetClientByID(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.RedirectURIs, uris) || !reflect.DeepEqual(got.Scopes, scopes) {
		t.Errorf("round trip mismatch: %q / %q", got.RedirectURIs, got.Scopes)
	}
}

// TestRuntimeConnectionIsUsableAfterMigrate guards the two-DSN deployment
// model: Migrate (admin) and OpenWithTLS (runtime) are independent handles.
func TestRuntimeConnectionIsUsableAfterMigrate(t *testing.T) {
	db, dsn := newTestDB(t)
	second, err := OpenWithTLS(dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := db.CreateUser(context.Background(), "x@example.com", "h", "X"); err != nil {
		t.Fatal(err)
	}
	n, err := second.CountUsers(context.Background())
	if err != nil || n != 1 {
		t.Errorf("CountUsers via second handle = %d, %v; want 1", n, err)
	}
}
