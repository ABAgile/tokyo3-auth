// Package scim is the outbound SCIM 2.0 provisioner. It implements
// provision.Provisioner against any standards-compliant SCIM server (vault is
// the primary target; Okta/Azure-style endpoints work too).
//
// Self-heal: external_ids is a best-effort cache. On 404 from PUT/PATCH/DELETE
// the client invalidates the cache and re-resolves via `filter=externalId eq`
// (the subset filter introduced in vault Phase 2). If the downstream user
// genuinely no longer exists, write paths fall through to POST /Users —
// vault's POST is idempotent on email, so this safely handles "user exists
// downstream with a different ID and no externalId" cases.
package scim

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// ProviderName is the value stored in auth.external_ids.provider for users
// provisioned to vault. The same provisioner can be re-used for any other
// SCIM target by choosing a different name in Config.
const ProviderName = "vault"

const (
	schemaUser    = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup   = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaPatchOp = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

	contentTypeSCIM = "application/scim+json"
	defaultTimeout  = 10 * time.Second
)

// errStatusNotFound is the sentinel returned by do() on 404 — used by
// self-heal paths to distinguish "downstream resource gone" from other errors.
var errStatusNotFound = errors.New("scim: 404")

// IDStore is the subset of store.Store needed for the external_ids cache.
type IDStore interface {
	GetExternalID(ctx context.Context, provider string, userID uuid.UUID) (string, error)
	SetExternalID(ctx context.Context, provider string, userID uuid.UUID, externalID string) error
	DeleteExternalID(ctx context.Context, provider string, userID uuid.UUID) error
}

// Config configures a Provisioner.
type Config struct {
	// Provider is the external_ids cache key (default "vault").
	Provider string
	// Name is reported via Provisioner.Name (default "vault-scim").
	Name string
	// BaseURL is vault's SCIM root, e.g. https://vault.example.com/scim/v2.
	BaseURL string
	// Token is the bearer credential issued by the downstream. Leave empty
	// when authenticating via mTLS (TLSConfig must then be non-nil).
	Token string
	// Timeout is the per-request HTTP timeout (default 10s).
	Timeout time.Duration
	// TLSConfig is used as the HTTP transport's TLSClientConfig when non-nil.
	// In mTLS mode it carries GetClientCertificate (hot-reloading) and an
	// optional RootCAs bundle. nil = stdlib defaults (system roots, no client cert).
	TLSConfig *tls.Config
	// Store is the auth-side cache for downstream UUIDs.
	Store IDStore
	// Log receives non-fatal warnings (cache write failures, member resolution).
	Log *slog.Logger
}

// Provisioner is the outbound SCIM client implementing provision.Provisioner.
type Provisioner struct {
	provider string
	name     string
	baseURL  string
	token    string
	client   *http.Client
	store    IDStore
	log      *slog.Logger
}

// New constructs a Provisioner from Config. Required fields are BaseURL,
// Token, and Store; everything else has sensible defaults.
func New(cfg Config) *Provisioner {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	provider := cfg.Provider
	if provider == "" {
		provider = ProviderName
	}
	name := cfg.Name
	if name == "" {
		name = "vault-scim"
	}
	client := &http.Client{Timeout: timeout}
	if cfg.TLSConfig != nil {
		client.Transport = &http.Transport{TLSClientConfig: cfg.TLSConfig}
	}
	return &Provisioner{
		provider: provider,
		name:     name,
		baseURL:  strings.TrimRight(cfg.BaseURL, "/"),
		token:    cfg.Token,
		client:   client,
		store:    cfg.Store,
		log:      cfg.Log,
	}
}

// Name implements provision.Provisioner.
func (p *Provisioner) Name() string { return p.name }

// User implements provision.Provisioner.
func (p *Provisioner) User(ctx context.Context, op provision.Op, u *model.User, _ []string) error {
	switch op {
	case provision.OpCreate, provision.OpUpdate:
		_, err := p.upsertUser(ctx, u)
		return err
	case provision.OpDeactivate:
		return p.setUserActive(ctx, u, false)
	case provision.OpDelete:
		return p.deleteUser(ctx, u)
	}
	return fmt.Errorf("scim: unknown user op %v", op)
}

// Group implements provision.Provisioner.
func (p *Provisioner) Group(ctx context.Context, op provision.Op, g *model.SCIMGroup, members []*model.User) error {
	switch op {
	case provision.OpDelete:
		return p.deleteGroup(ctx, g)
	default:
		return p.upsertGroup(ctx, g, members)
	}
}

// ── User helpers ──────────────────────────────────────────────────────────────

// upsertUser ensures vault has a record matching auth's u, returning vault's
// user ID. Cache hit: PATCH; cache miss or 404: POST (idempotent on email).
func (p *Provisioner) upsertUser(ctx context.Context, u *model.User) (string, error) {
	vaultID, err := p.cachedExternalID(ctx, u.ID)
	if err != nil {
		return "", err
	}
	if vaultID != "" {
		err := p.patchUser(ctx, vaultID, u)
		if err == nil {
			return vaultID, nil
		}
		if !errors.Is(err, errStatusNotFound) {
			return "", err
		}
		// Stale cache: clear and re-create.
		_ = p.store.DeleteExternalID(ctx, p.provider, u.ID)
	}
	return p.createUser(ctx, u)
}

func (p *Provisioner) createUser(ctx context.Context, u *model.User) (string, error) {
	body := map[string]any{
		"schemas":    []string{schemaUser},
		"userName":   u.Email,
		"externalId": u.ID.String(),
		"name":       map[string]any{"formatted": u.Name},
		"emails":     []map[string]any{{"value": u.Email, "primary": true, "type": "work"}},
		"active":     u.Active,
	}
	var resp struct {
		ID string `json:"id"`
	}
	if _, err := p.do(ctx, http.MethodPost, "/Users", body, &resp); err != nil {
		return "", err
	}
	if resp.ID == "" {
		return "", errors.New("scim: create user response missing id")
	}
	if err := p.store.SetExternalID(ctx, p.provider, u.ID, resp.ID); err != nil && p.log != nil {
		p.log.Warn("scim: persist external id", "user", u.Email, "err", err)
	}
	return resp.ID, nil
}

func (p *Provisioner) patchUser(ctx context.Context, vaultID string, u *model.User) error {
	body := map[string]any{
		"schemas": []string{schemaPatchOp},
		"Operations": []map[string]any{
			{"op": "Replace", "path": "active", "value": u.Active},
			{"op": "Replace", "path": "name.formatted", "value": u.Name},
		},
	}
	_, err := p.do(ctx, http.MethodPatch, "/Users/"+url.PathEscape(vaultID), body, nil)
	return err
}

func (p *Provisioner) setUserActive(ctx context.Context, u *model.User, active bool) error {
	vaultID, err := p.resolveVaultUserID(ctx, u)
	if err != nil {
		return err
	}
	if vaultID == "" {
		// User isn't in vault. Deactivate is a no-op.
		return nil
	}
	body := map[string]any{
		"schemas": []string{schemaPatchOp},
		"Operations": []map[string]any{
			{"op": "Replace", "path": "active", "value": active},
		},
	}
	_, err = p.do(ctx, http.MethodPatch, "/Users/"+url.PathEscape(vaultID), body, nil)
	if errors.Is(err, errStatusNotFound) {
		_ = p.store.DeleteExternalID(ctx, p.provider, u.ID)
		return nil
	}
	return err
}

func (p *Provisioner) deleteUser(ctx context.Context, u *model.User) error {
	vaultID, err := p.resolveVaultUserID(ctx, u)
	if err != nil {
		return err
	}
	if vaultID == "" {
		return nil
	}
	_, err = p.do(ctx, http.MethodDelete, "/Users/"+url.PathEscape(vaultID), nil, nil)
	if err == nil || errors.Is(err, errStatusNotFound) {
		_ = p.store.DeleteExternalID(ctx, p.provider, u.ID)
	}
	if errors.Is(err, errStatusNotFound) {
		return nil
	}
	return err
}

// resolveVaultUserID returns vault's user UUID for u, using the local cache
// then a `filter=externalId eq` query as fallback. Returns ("", nil) when the
// user does not exist in vault — callers decide whether that's an error.
func (p *Provisioner) resolveVaultUserID(ctx context.Context, u *model.User) (string, error) {
	if id, err := p.cachedExternalID(ctx, u.ID); err != nil {
		return "", err
	} else if id != "" {
		return id, nil
	}
	id, err := p.findUserByExternalID(ctx, u.ID.String())
	if err != nil || id == "" {
		return id, err
	}
	if err := p.store.SetExternalID(ctx, p.provider, u.ID, id); err != nil && p.log != nil {
		p.log.Warn("scim: persist external id", "user", u.Email, "err", err)
	}
	return id, nil
}

func (p *Provisioner) cachedExternalID(ctx context.Context, userID uuid.UUID) (string, error) {
	id, err := p.store.GetExternalID(ctx, p.provider, userID)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return id, err
}

func (p *Provisioner) findUserByExternalID(ctx context.Context, externalID string) (string, error) {
	q := url.Values{}
	q.Set("filter", `externalId eq `+jsonString(externalID))
	var resp struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if _, err := p.do(ctx, http.MethodGet, "/Users?"+q.Encode(), nil, &resp); err != nil {
		return "", err
	}
	if len(resp.Resources) == 0 {
		return "", nil
	}
	return resp.Resources[0].ID, nil
}

// ── Group helpers ─────────────────────────────────────────────────────────────

func (p *Provisioner) upsertGroup(ctx context.Context, g *model.SCIMGroup, members []*model.User) error {
	memberRefs, err := p.resolveGroupMembers(ctx, members)
	if err != nil {
		return err
	}
	vaultGroupID, err := p.findGroupByDisplayName(ctx, g.DisplayName)
	if err != nil {
		return err
	}
	body := map[string]any{
		"schemas":     []string{schemaGroup},
		"displayName": g.DisplayName,
		"members":     memberRefs,
	}
	if vaultGroupID == "" {
		_, err := p.do(ctx, http.MethodPost, "/Groups", body, nil)
		return err
	}
	_, err = p.do(ctx, http.MethodPut, "/Groups/"+url.PathEscape(vaultGroupID), body, nil)
	if errors.Is(err, errStatusNotFound) {
		// Vault no longer has this group; recreate.
		_, err = p.do(ctx, http.MethodPost, "/Groups", body, nil)
	}
	return err
}

func (p *Provisioner) deleteGroup(ctx context.Context, g *model.SCIMGroup) error {
	vaultGroupID, err := p.findGroupByDisplayName(ctx, g.DisplayName)
	if err != nil || vaultGroupID == "" {
		return err
	}
	_, err = p.do(ctx, http.MethodDelete, "/Groups/"+url.PathEscape(vaultGroupID), nil, nil)
	if errors.Is(err, errStatusNotFound) {
		return nil
	}
	return err
}

func (p *Provisioner) findGroupByDisplayName(ctx context.Context, displayName string) (string, error) {
	q := url.Values{}
	q.Set("filter", `displayName eq `+jsonString(displayName))
	var resp struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if _, err := p.do(ctx, http.MethodGet, "/Groups?"+q.Encode(), nil, &resp); err != nil {
		return "", err
	}
	if len(resp.Resources) == 0 {
		return "", nil
	}
	return resp.Resources[0].ID, nil
}

// resolveGroupMembers maps each auth user to its vault UUID. Members that
// cannot be resolved (and cannot be created on the spot) are logged and
// skipped — group sync is best-effort.
func (p *Provisioner) resolveGroupMembers(ctx context.Context, members []*model.User) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		vaultID, err := p.resolveVaultUserID(ctx, m)
		if err != nil {
			if p.log != nil {
				p.log.Warn("scim: resolve group member", "user", m.Email, "err", err)
			}
			continue
		}
		if vaultID == "" {
			// Member not provisioned yet — create on the spot to keep the
			// group consistent.
			if vaultID, err = p.createUser(ctx, m); err != nil {
				if p.log != nil {
					p.log.Warn("scim: create group member", "user", m.Email, "err", err)
				}
				continue
			}
		}
		out = append(out, map[string]any{"value": vaultID})
	}
	return out, nil
}

// ── HTTP plumbing ─────────────────────────────────────────────────────────────

// do issues an HTTP request to the SCIM endpoint and decodes the JSON response
// into out (when non-nil). 404 is reported via errStatusNotFound so callers can
// trigger self-heal; other 4xx/5xx surface a wrapped error with body excerpt.
func (p *Provisioner) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("scim: marshal body: %w", err)
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.baseURL+path, rd)
	if err != nil {
		return 0, err
	}
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	req.Header.Set("Accept", contentTypeSCIM)
	if body != nil {
		req.Header.Set("Content-Type", contentTypeSCIM)
	}
	res, err := p.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	switch {
	case res.StatusCode == http.StatusNotFound:
		return res.StatusCode, errStatusNotFound
	case res.StatusCode >= 400:
		excerpt, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return res.StatusCode, fmt.Errorf("scim %s %s: %d: %s",
			method, path, res.StatusCode, bytes.TrimSpace(excerpt))
	}
	if out != nil {
		dec := json.NewDecoder(res.Body)
		if err := dec.Decode(out); err != nil && err != io.EOF {
			return res.StatusCode, fmt.Errorf("scim: decode response: %w", err)
		}
	}
	return res.StatusCode, nil
}

// jsonString JSON-encodes s as a quoted string. Used to safely build SCIM
// filter expressions (`displayName eq "value with \"quotes\""`).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
