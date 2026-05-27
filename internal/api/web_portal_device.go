package api

import (
	"crypto/rand"
	"net/http"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	creds "github.com/abagile/tokyo3-base/auth/creds"
	"github.com/google/uuid"
)

// Device authorization grant (RFC 8628). The CLI starts at
// /device_authorization (public POST, no user session yet — the
// client_id is the only thing tying the request to a registered
// client). The user lands at /device on whatever browser they have
// handy, types the user_code, approves at /device/confirm. The CLI
// polls /token with grant_type=urn:ietf:params:oauth:grant-type:device_code
// at the configured interval until the grant is approved (or denied
// or expired).
//
// The user_code lives behind portalAuth — we want a known user
// confirming the approval, both for audit and so the issued bearer
// session inherits their identity + MFA state. /device_authorization
// itself is public (the device hasn't authenticated as anyone yet),
// gated only by the client's allow_device_grant flag.

const (
	// deviceCodeTTL bounds how long a pending device authorization may
	// sit between mint and approval. 15 min mirrors the IETF reference
	// implementations and gives users headroom to switch devices.
	deviceCodeTTL = 15 * time.Minute
	// defaultDevicePollInterval is the floor on how often the CLI may
	// poll /token. slow_down bumps it by this same step when the CLI
	// outpaces the configured rate.
	defaultDevicePollInterval = 5
)

// userCodeAlphabet is base32-minus-ambiguous-chars: A-Z minus I/O,
// plus 2-9. 32 characters of 5 bits each → an 8-character user_code
// carries ~40 bits of entropy, more than enough for the 15-min
// validity window even without rate limits (and we apply rate limits
// in addition).
const userCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// handleDeviceAuthorization is RFC 8628 §3.1. Public endpoint.
func (s *Server) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	if clientID == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	client, err := s.store.GetClientByClientID(r.Context(), clientID)
	if err != nil || !client.AllowDeviceGrant {
		// Same error shape regardless of whether the client_id is
		// unknown or just not opted in — don't help probers enumerate
		// the client registry.
		s.writeError(w, http.StatusBadRequest, "unauthorized_client",
			"this client is not authorized to use the device authorization grant")
		return
	}

	scopes := splitScopes(strings.TrimSpace(r.FormValue("scope")))
	if len(scopes) == 0 {
		scopes = client.Scopes
	}
	for _, sc := range scopes {
		if !containsStr(client.Scopes, sc) {
			s.writeError(w, http.StatusBadRequest, "invalid_scope",
				"requested scope is not registered for this client: "+sc)
			return
		}
	}

	deviceCode, err := generateDeviceCode()
	if err != nil {
		s.log.Error("device_authorization: device_code gen", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "code generation failed")
		return
	}
	userCode, err := generateUserCode()
	if err != nil {
		s.log.Error("device_authorization: user_code gen", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "code generation failed")
		return
	}

	grant := &model.DeviceGrant{
		ID:             uuid.New(),
		DeviceCodeHash: creds.HashToken(deviceCode),
		UserCodeHash:   creds.HashToken(normalizeUserCode(userCode)),
		ClientID:       client.ID,
		Scopes:         scopes,
		Status:         model.DeviceGrantStatusPending,
		IntervalSec:    defaultDevicePollInterval,
		ExpiresAt:      time.Now().Add(deviceCodeTTL),
	}
	if err := s.store.CreateDeviceGrant(r.Context(), grant); err != nil {
		s.log.Error("device_authorization: persist", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "could not create grant")
		return
	}
	if err := s.logAudit(r, ActionDeviceAuthorizationCreated, nil, &client.ID,
		logMeta("grant_id", grant.ID.String(), "scopes", scopes)); err != nil {
		s.auditFail(w, err)
		return
	}

	verificationURI := strings.TrimRight(s.issuer, "/") + "/device"
	s.writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + userCode,
		"expires_in":                int(deviceCodeTTL.Seconds()),
		"interval":                  grant.IntervalSec,
	})
}

// deviceEntryData backs portal_device.html — code entry form.
type deviceEntryData struct {
	Error    string
	UserCode string
}

// deviceConfirmData backs portal_device_confirm.html — Approve/Deny
// page after a valid user_code has been entered. Renders the client
// name + scopes + approver IP so the user can sanity-check before
// approving.
type deviceConfirmData struct {
	GrantID    string
	UserCode   string
	ClientName string
	Scopes     []string
	ApproverIP string
}

// deviceDoneData backs portal_device_done.html — the terminal page
// shown after Approve/Deny so the user knows they can return to the
// originating device.
type deviceDoneData struct {
	Approved bool
	Error    string
}

// handleDevice serves both GET (code entry, optionally pre-filled
// from ?user_code) and POST (validate code, show confirmation page).
// Wraps in portalAuth so we always know the approver's identity.
func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userCode := strings.TrimSpace(r.FormValue("user_code"))
	if userCode == "" {
		userCode = strings.TrimSpace(r.URL.Query().Get("user_code"))
	}

	render := func(errMsg string) {
		s.ssoTmpl.render(w, "portal_device.html", deviceEntryData{
			Error: errMsg, UserCode: userCode,
		})
	}

	if r.Method == http.MethodGet {
		render("")
		return
	}

	if userCode == "" {
		render("Enter the code shown by your device.")
		return
	}
	normalized := normalizeUserCode(userCode)
	grant, err := s.store.GetDeviceGrantByUserCodeHash(r.Context(), creds.HashToken(normalized))
	if err != nil {
		render("Invalid or expired code.")
		return
	}
	if grant.Status != model.DeviceGrantStatusPending || time.Now().After(grant.ExpiresAt) {
		render("Invalid or expired code.")
		return
	}

	client, err := s.store.GetClientByID(r.Context(), grant.ClientID)
	if err != nil {
		s.log.Error("device: client lookup", "err", err)
		render("Internal error; please try again.")
		return
	}
	s.ssoTmpl.render(w, "portal_device_confirm.html", deviceConfirmData{
		GrantID:    grant.ID.String(),
		UserCode:   userCode,
		ClientName: client.Name,
		Scopes:     grant.Scopes,
		ApproverIP: clientIP(r),
	})
}

// handleDeviceConfirm processes the Approve / Deny click.
func (s *Server) handleDeviceConfirm(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()
	grantID, err := uuid.Parse(r.FormValue("grant_id"))
	if err != nil {
		http.Redirect(w, r, "/device?error="+
			"invalid+grant", http.StatusFound)
		return
	}
	approverIP := clientIP(r)
	action := r.FormValue("action")

	switch action {
	case "approve":
		if err := s.store.MarkDeviceGrantApproved(r.Context(), grantID,
			pc.User.ID, pc.Session.MFAVerified, pc.Session.MFAVerifiedAt, approverIP); err != nil {
			s.ssoTmpl.render(w, "portal_device_done.html", deviceDoneData{
				Error: "This code has already been processed or expired.",
			})
			return
		}
		if err := s.logAudit(r, ActionDeviceCodeApproved, &pc.User.ID, nil,
			logMeta("grant_id", grantID.String(), "ip", approverIP, "mfa_verified", pc.Session.MFAVerified)); err != nil {
			s.auditFail(w, err)
			return
		}
		s.ssoTmpl.render(w, "portal_device_done.html", deviceDoneData{Approved: true})
	case "deny":
		_ = s.store.MarkDeviceGrantDenied(r.Context(), grantID, approverIP)
		if err := s.logAudit(r, ActionDeviceCodeDenied, &pc.User.ID, nil,
			logMeta("grant_id", grantID.String(), "ip", approverIP)); err != nil {
			s.auditFail(w, err)
			return
		}
		s.ssoTmpl.render(w, "portal_device_done.html", deviceDoneData{Approved: false})
	default:
		http.Redirect(w, r, "/device?error=invalid+action", http.StatusFound)
	}
}

// handleTokenDeviceCode is RFC 8628 §3.4 — the polling endpoint. The
// CLI sends device_code + client_id; we look up the grant by hash and
// translate its state into the RFC error codes:
//
//	pending  → 400 authorization_pending
//	pending+stale-poll → 400 slow_down (interval bumped on the row)
//	expired  → 400 expired_token
//	denied   → 400 access_denied
//	approved → 200 tokens (and atomically mark redeemed)
//	redeemed → 400 invalid_grant (single-use replay protection)
func (s *Server) handleTokenDeviceCode(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.FormValue("device_code")
	clientID := r.FormValue("client_id")
	if deviceCode == "" || clientID == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "device_code and client_id are required")
		return
	}
	client, err := s.store.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	grant, err := s.store.GetDeviceGrantByDeviceCodeHash(r.Context(), creds.HashToken(deviceCode))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "expired_token", "device_code not found or expired")
		return
	}
	if grant.ClientID != client.ID {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}

	now := time.Now()
	if now.After(grant.ExpiresAt) {
		s.writeError(w, http.StatusBadRequest, "expired_token", "device_code expired; restart the flow")
		return
	}

	switch grant.Status {
	case model.DeviceGrantStatusDenied:
		s.writeError(w, http.StatusBadRequest, "access_denied", "user denied the authorization request")
		return
	case model.DeviceGrantStatusExpired:
		s.writeError(w, http.StatusBadRequest, "expired_token", "device_code expired")
		return
	case model.DeviceGrantStatusRedeemed:
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "device_code already redeemed")
		return
	case model.DeviceGrantStatusPending:
		// Polled too soon? Slow-down. Record this poll (best-effort).
		interval := grant.IntervalSec
		if grant.LastPolledAt != nil && now.Sub(*grant.LastPolledAt) < time.Duration(interval)*time.Second {
			interval += defaultDevicePollInterval
			_ = s.store.UpdateDeviceGrantPoll(r.Context(), grant.ID, now, interval)
			s.writeError(w, http.StatusBadRequest, "slow_down",
				"polling too frequently; back off")
			return
		}
		_ = s.store.UpdateDeviceGrantPoll(r.Context(), grant.ID, now, interval)
		s.writeError(w, http.StatusBadRequest, "authorization_pending",
			"waiting for user to approve")
		return
	case model.DeviceGrantStatusApproved:
		// Single-use: mark redeemed atomically before issuing tokens.
		// If the CAS fails it means a concurrent /token poll redeemed
		// first (unlikely but possible if a CLI is unlucky enough to
		// fire two requests within the same RTT). Bail with invalid_grant.
		if err := s.store.MarkDeviceGrantRedeemed(r.Context(), grant.ID); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_grant", "device_code already redeemed")
			return
		}
		if grant.UserID == nil {
			s.writeError(w, http.StatusInternalServerError, "server_error", "approved grant has no user")
			return
		}
		user, err := s.store.GetUserByID(r.Context(), *grant.UserID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "server_error", "approver not found")
			return
		}
		if !user.Active {
			s.writeError(w, http.StatusForbidden, "access_denied", "approver account is inactive")
			return
		}
		resp, err := s.mintTokenResponseWithMFAAt(r, user, client, grant.Scopes,
			grant.MFAVerified, grant.MFAVerifiedAt, "")
		if err != nil {
			s.log.Error("device token mint", "err", err)
			s.writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
			return
		}
		if err := s.logAudit(r, ActionDeviceCodeRedeemed, &user.ID, &client.ID,
			logMeta("grant_id", grant.ID.String(), "scopes", grant.Scopes)); err != nil {
			s.auditFail(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, resp)
		return
	default:
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "unknown grant state")
		return
	}
}

// generateDeviceCode mints the long opaque bearer the CLI sends back
// to /token. Sized like other auth tokens in this codebase (32 random
// bytes → base64url) so its entropy is equivalent to a refresh token.
func generateDeviceCode() (string, error) {
	return creds.GenerateRawToken()
}

// generateUserCode produces a 4-4 hyphenated code from the
// ambiguity-stripped 32-char alphabet. 40 bits of entropy in 8 chars;
// hyphenation is purely cosmetic and stripped before hashing.
func generateUserCode() (string, error) {
	const codeLen = 8
	buf := make([]byte, codeLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, 0, codeLen+1)
	for i, b := range buf {
		out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
		if i == 3 {
			out = append(out, '-')
		}
	}
	return string(out), nil
}

// normalizeUserCode strips whitespace and hyphens and uppercases the
// remaining characters. The hashed form is what's stored, so any
// formatting the user adds while typing (extra spaces, lowercase) is
// transparently accepted.
func normalizeUserCode(in string) string {
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c == ' ' || c == '-' || c == '\t' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}
