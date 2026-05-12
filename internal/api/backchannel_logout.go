package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// backchannelLogoutTimeout caps each individual logout_token POST. RPs are
// expected to respond fast (the spec recommends just acknowledging then
// processing async). Five seconds is generous enough for a healthy RP and
// short enough to keep the originating logout snappy when multiple RPs
// need to be notified.
const backchannelLogoutTimeout = 5 * time.Second

// broadcastLogout fan-outs an OIDC Back-Channel Logout 1.0 notification to
// every RP that has registered a backchannel_logout_uri and currently holds
// at least one session for userID. When sid is non-empty the notification
// is session-scoped (RPs use it to invalidate exactly that session row);
// when empty it's a whole-user logout. The portal sentinel client is always
// skipped — auth doesn't broadcast to itself.
//
// Fire-and-forget: each push runs to completion (or its 5s timeout) but the
// caller doesn't wait for the result, and a failure on one RP doesn't block
// the others. Failures are audit-logged with the http status / error in
// metadata so post-mortems can correlate.
//
// The originating logout (DeleteSession, DeleteSessionsByUserID, …) happens
// independently of this call — RPs can rely on the OP killing its own state
// regardless of whether the broadcast succeeded.
func (s *Server) broadcastLogout(ctx context.Context, r *http.Request, userID uuid.UUID, sid string) {
	if s.signer == nil {
		return
	}
	clientIDs, err := s.store.ListSessionClientIDsByUser(ctx, userID)
	if err != nil {
		s.log.Warn("backchannel logout: list session clients", "user_id", userID, "err", err)
		return
	}
	if len(clientIDs) == 0 {
		return
	}
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		s.log.Warn("backchannel logout: lookup user", "user_id", userID, "err", err)
		return
	}
	for _, cid := range clientIDs {
		if cid == portalClientUUID {
			continue
		}
		client, err := s.store.GetClientByID(ctx, cid)
		if err != nil {
			s.log.Warn("backchannel logout: lookup client", "client_id", cid, "err", err)
			continue
		}
		if client.BackchannelLogoutURI == nil || strings.TrimSpace(*client.BackchannelLogoutURI) == "" {
			continue
		}
		go s.pushLogoutToken(r, client.ID, *client.BackchannelLogoutURI, client.ClientID, user.ID.String(), sid)
	}
}

// pushLogoutToken mints a single logout_token and POSTs it to one RP's
// backchannel_logout_uri. Runs in its own goroutine spawned by
// broadcastLogout; uses a fresh detached context so a finishing HTTP handler
// doesn't cancel the in-flight notification mid-send.
func (s *Server) pushLogoutToken(r *http.Request, clientDBID uuid.UUID, logoutURI, clientID, sub, sid string) {
	ctx, cancel := context.WithTimeout(context.Background(), backchannelLogoutTimeout)
	defer cancel()

	jti := uuid.NewString()
	token, err := s.signer.MintLogoutToken(clientID, sub, sid, jti, time.Now().UTC())
	if err != nil {
		s.log.Error("backchannel logout: mint", "client_id", clientID, "err", err)
		_ = s.logAudit(r, ActionBackchannelLogout, nil, &clientDBID,
			logMeta("status", "mint_failed", "err", err.Error(), "jti", jti))
		return
	}

	form := url.Values{"logout_token": []string{token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutURI, strings.NewReader(form.Encode()))
	if err != nil {
		s.log.Error("backchannel logout: build request", "uri", logoutURI, "err", err)
		_ = s.logAudit(r, ActionBackchannelLogout, nil, &clientDBID,
			logMeta("status", "build_failed", "err", err.Error(), "jti", jti, "uri", logoutURI))
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := &http.Client{Timeout: backchannelLogoutTimeout}
	if s.outboundTLS != nil {
		httpClient.Transport = &http.Transport{TLSClientConfig: s.outboundTLS}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		s.log.Warn("backchannel logout: POST failed", "uri", logoutURI, "err", err)
		_ = s.logAudit(r, ActionBackchannelLogout, nil, &clientDBID,
			logMeta("status", "dial_failed", "err", err.Error(), "jti", jti, "uri", logoutURI))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.log.Warn("backchannel logout: RP returned non-2xx", "uri", logoutURI, "status", resp.StatusCode)
		_ = s.logAudit(r, ActionBackchannelLogout, nil, &clientDBID,
			logMeta("status", "http_error", "http_status", resp.StatusCode, "jti", jti, "uri", logoutURI))
		return
	}
	_ = s.logAudit(r, ActionBackchannelLogout, nil, &clientDBID,
		logMeta("status", "ok", "http_status", resp.StatusCode, "jti", jti, "uri", logoutURI,
			"scope", logoutScope(sid)))
}

func logoutScope(sid string) string {
	if sid == "" {
		return "user"
	}
	return "session"
}

// formatBackchannelErr is reserved for future structured error logging if
// we want richer audit metadata than the current logMeta key/value pairs.
var _ = fmt.Sprintf
