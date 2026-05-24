package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abagile/tokyo3-auth/internal/audit"
	internaljwt "github.com/abagile/tokyo3-auth/internal/jwt"
	"github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/policy"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/store/sqlite"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/abagile/tokyo3-base/journal"
)

// testRig bundles the dependencies a handler needs, along with the HTTP
// test server. Spawned by newTestRig; teardown runs via t.Cleanup.
type testRig struct {
	srv    *httptest.Server
	server *Server
	store  *sqlite.DB
	kp     bcrypto.KeyProvider
	signer *internaljwt.Signer
	mk     []byte
}

// newTestRig wires an in-memory sqlite store, a LocalKeyProvider with a fresh
// 32-byte master key, a freshly-minted signer, the default PCI policy, and
// returns an httptest.Server fronting the api.Server's routes.
func newTestRig(t *testing.T) *testRig {
	t.Helper()
	ctx := context.Background()

	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mk, err := bcrypto.RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	kp := bcrypto.NewLocalKeyProvider(mk)

	signer, err := internaljwt.LoadOrCreate(ctx, db, kp, "https://issuer.test")
	if err != nil {
		t.Fatalf("LoadOrCreate signer: %v", err)
	}

	wa, err := mfa.NewWAHandler("localhost", "test", []string{"https://localhost"}, db)
	if err != nil {
		t.Fatalf("NewWAHandler: %v", err)
	}

	// Empty provisioner registry — exercises the realistic "no integrations
	// configured" branch in handlers that walk the registry. Tests that
	// need an awsfed or scim provisioner inject their own via the builder.
	provReg := provision.NewRegistry(func(ctx context.Context) (*provision.Set, error) {
		return &provision.Set{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, nil
	})
	if err := provReg.Reload(ctx); err != nil {
		t.Fatalf("provReg.Reload: %v", err)
	}

	api, err := New(Config{
		Store:        db,
		Signer:       signer,
		Policy:       policy.New(policy.DefaultPCIRules()...),
		WAHandler:    wa,
		KP:           kp,
		Provisioners: provReg,
		Audit:        audit.NoopSink,
		AuditSource:  journal.NoopSource{},
		Issuer:       "https://issuer.test",
		// AWSAudience non-empty in the default rig so federation handlers
		// reach their authorization checks (which is what most tests
		// exercise). The dedicated "federation_disabled" test instantiates
		// its own rig with this field empty.
		AWSAudience:       "tokyo3-aws-test",
		MasterKey:         mk,
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowRegistration: true,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}

	srv := httptest.NewServer(api.Routes())
	t.Cleanup(srv.Close)

	return &testRig{srv: srv, server: api, store: db, kp: kp, signer: signer, mk: mk}
}

// get issues a GET to the rig's server. The client does not follow redirects
// so handlers that 302 on success can be asserted directly.
func (r *testRig) get(t *testing.T, path string) *http.Response {
	t.Helper()
	c := &http.Client{CheckRedirect: noFollow}
	resp, err := c.Get(r.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

// postForm issues a POST with application/x-www-form-urlencoded body.
func (r *testRig) postForm(t *testing.T, path, body string) *http.Response {
	t.Helper()
	c := &http.Client{CheckRedirect: noFollow}
	resp, err := c.Post(r.srv.URL+path, "application/x-www-form-urlencoded", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// decodeJSON reads the response body and unmarshals it. Closes the body.
func decodeJSON[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return out
}

func noFollow(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
