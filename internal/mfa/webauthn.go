package mfa

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// WAUser adapts model.User to the webauthn.User interface.
type WAUser struct {
	user  *model.User
	creds []*model.WebAuthnCredential
}

func newWAUser(u *model.User, creds []*model.WebAuthnCredential) *WAUser {
	return &WAUser{user: u, creds: creds}
}

func (w *WAUser) WebAuthnID() []byte                         { return w.user.ID[:] }
func (w *WAUser) WebAuthnName() string                       { return w.user.Email }
func (w *WAUser) WebAuthnDisplayName() string                { return w.user.Name }
func (w *WAUser) WebAuthnCredentials() []webauthn.Credential { return w.modelToWACreds() }

func (w *WAUser) modelToWACreds() []webauthn.Credential {
	out := make([]webauthn.Credential, len(w.creds))
	for i, c := range w.creds {
		out[i] = webauthn.Credential{
			ID:        c.CredentialID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		}
	}
	return out
}

// WAHandler wraps the go-webauthn library and the store.
type WAHandler struct {
	wa *webauthn.WebAuthn
	st store.MFAStore
}

// NewWAHandler creates a WebAuthn handler.
func NewWAHandler(rpID, rpDisplayName string, origins []string, st store.MFAStore) (*WAHandler, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn init: %w", err)
	}
	return &WAHandler{wa: wa, st: st}, nil
}

// BeginRegistration starts credential enrollment and returns challenge options + session ID.
func (h *WAHandler) BeginRegistration(ctx context.Context, user *model.User) (optionsJSON []byte, sessionID uuid.UUID, err error) {
	creds, _ := h.st.ListWebAuthnCredentials(ctx, user.ID)
	waUser := newWAUser(user, creds)

	options, sessionData, err := h.wa.BeginRegistration(waUser)
	if err != nil {
		return nil, uuid.UUID{}, fmt.Errorf("begin registration: %w", err)
	}
	optionsJSON, err = json.Marshal(options)
	if err != nil {
		return nil, uuid.UUID{}, err
	}
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, uuid.UUID{}, err
	}
	sessionID, err = h.st.CreateWebAuthnSession(ctx, user.ID, sessionBytes, "register")
	if err != nil {
		return nil, uuid.UUID{}, err
	}
	return optionsJSON, sessionID, nil
}

// FinishRegistration completes enrollment from the HTTP request body.
func (h *WAHandler) FinishRegistration(ctx context.Context, user *model.User, sessionID uuid.UUID, r *http.Request, deviceName string) (*model.WebAuthnCredential, error) {
	sessionBytes, err := h.st.GetWebAuthnSession(ctx, sessionID, user.ID, "register")
	if err != nil {
		return nil, fmt.Errorf("webauthn session not found")
	}
	_ = h.st.DeleteWebAuthnSession(ctx, sessionID)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &sessionData); err != nil {
		return nil, err
	}
	creds, _ := h.st.ListWebAuthnCredentials(ctx, user.ID)
	waUser := newWAUser(user, creds)

	cred, err := h.wa.FinishRegistration(waUser, sessionData, r)
	if err != nil {
		return nil, fmt.Errorf("finish registration: %w", err)
	}

	m := &model.WebAuthnCredential{
		ID:           uuid.New(),
		UserID:       user.ID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		AAGUID:       cred.Authenticator.AAGUID,
		SignCount:    cred.Authenticator.SignCount,
		DeviceName:   deviceName,
	}
	if err := h.st.CreateWebAuthnCredential(ctx, m); err != nil {
		return nil, err
	}
	return m, nil
}

// BeginLogin starts an assertion flow.
func (h *WAHandler) BeginLogin(ctx context.Context, user *model.User) (optionsJSON []byte, sessionID uuid.UUID, err error) {
	creds, err := h.st.ListWebAuthnCredentials(ctx, user.ID)
	if err != nil || len(creds) == 0 {
		return nil, uuid.UUID{}, fmt.Errorf("no WebAuthn credentials registered")
	}
	waUser := newWAUser(user, creds)

	options, sessionData, err := h.wa.BeginLogin(waUser)
	if err != nil {
		return nil, uuid.UUID{}, fmt.Errorf("begin login: %w", err)
	}
	optionsJSON, err = json.Marshal(options)
	if err != nil {
		return nil, uuid.UUID{}, err
	}
	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, uuid.UUID{}, err
	}
	sessionID, err = h.st.CreateWebAuthnSession(ctx, user.ID, sessionBytes, "login")
	return optionsJSON, sessionID, err
}

// FinishLogin verifies the assertion from the HTTP request body and updates sign count.
// Returns "hwk" as the AMR value (hardware key / platform authenticator).
func (h *WAHandler) FinishLogin(ctx context.Context, user *model.User, sessionID uuid.UUID, r *http.Request) (amr string, err error) {
	sessionBytes, err := h.st.GetWebAuthnSession(ctx, sessionID, user.ID, "login")
	if err != nil {
		return "", fmt.Errorf("webauthn session not found")
	}
	_ = h.st.DeleteWebAuthnSession(ctx, sessionID)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &sessionData); err != nil {
		return "", err
	}
	creds, _ := h.st.ListWebAuthnCredentials(ctx, user.ID)
	waUser := newWAUser(user, creds)

	cred, err := h.wa.FinishLogin(waUser, sessionData, r)
	if err != nil {
		return "", fmt.Errorf("finish login: %w", err)
	}

	if stored, err := h.st.GetWebAuthnCredentialByCredentialID(ctx, cred.ID); err == nil {
		_ = h.st.UpdateWebAuthnSignCount(ctx, stored.ID, cred.Authenticator.SignCount, time.Now().UTC())
	}
	return "hwk", nil
}
