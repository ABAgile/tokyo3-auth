package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/abagile/tokyo3-auth/internal/auth"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// ── Users ─────────────────────────────────────────────────────────────────────

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "list failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"users": toUserViews(users)})
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
		Admin    bool   `json:"admin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" || req.Password == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "email and password required")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "hash failed")
		return
	}
	user, err := s.store.CreateUser(r.Context(), req.Email, hash, req.Name)
	if errors.Is(err, store.ErrConflict) {
		s.writeError(w, http.StatusConflict, "conflict", "user already exists")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "create failed")
		return
	}
	s.logAudit(r, ActionUserCreated, &user.ID, nil, logMeta("email", req.Email, "admin", req.Admin))
	s.provisionUser(r, provision.OpCreate, user, nil)
	s.writeJSON(w, http.StatusCreated, toUserView(user))
}

func (s *Server) handleAdminGetUser(w http.ResponseWriter, r *http.Request) {
	user, ok := s.adminParseUser(w, r)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, toUserView(user))
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	user, ok := s.adminParseUser(w, r)
	if !ok {
		return
	}
	var req struct {
		Name   string `json:"name"`
		Active *bool  `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}
	name := user.Name
	if req.Name != "" {
		name = req.Name
	}
	active := user.Active
	if req.Active != nil {
		active = *req.Active
	}
	if err := s.store.UpdateUser(r.Context(), user.ID, name, active); err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "update failed")
		return
	}
	s.logAudit(r, ActionUserUpdated, &user.ID, nil, logMeta("name", name, "active", active))
	user, _ = s.store.GetUserByID(r.Context(), user.ID)
	op := provision.OpUpdate
	if !active {
		op = provision.OpDeactivate
	}
	s.provisionUser(r, op, user, nil)
	s.writeJSON(w, http.StatusOK, toUserView(user))
}

func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	user, ok := s.adminParseUser(w, r)
	if !ok {
		return
	}
	_ = s.store.DeleteSessionsByUserID(r.Context(), user.ID)
	if err := s.store.DeleteUser(r.Context(), user.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "delete failed")
		return
	}
	s.logAudit(r, ActionUserDeleted, &user.ID, nil, nil)
	s.provisionUser(r, provision.OpDelete, user, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminParseUser(w http.ResponseWriter, r *http.Request) (*model.User, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid user id")
		return nil, false
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "not_found", "user not found")
		return nil, false
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "lookup failed")
		return nil, false
	}
	return user, true
}

// ── Clients ───────────────────────────────────────────────────────────────────

func (s *Server) handleAdminListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "list failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"clients": toClientViews(clients)})
}

func (s *Server) handleAdminCreateClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                 string   `json:"name"`
		RedirectURIs         []string `json:"redirect_uris"`
		Scopes               []string `json:"scopes"`
		Public               bool     `json:"public"`
		BackchannelLogoutURI string   `json:"backchannel_logout_uri,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}
	if req.Name == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "name required")
		return
	}
	rawClientID, err := auth.GenerateRawToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "generation failed")
		return
	}
	clientID := rawClientID[:24] // shorter, readable client_id
	var secretHash, rawSecret string
	if !req.Public {
		rawSecret, err = auth.GenerateRawToken()
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "server_error", "generation failed")
			return
		}
		secretHash = auth.HashToken(rawSecret)
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"openid", "profile", "email"}
	}
	var backchannelLogoutURI *string
	if req.BackchannelLogoutURI != "" {
		backchannelLogoutURI = &req.BackchannelLogoutURI
	}
	client, err := s.store.CreateClient(r.Context(), clientID, secretHash, req.Name, req.RedirectURIs, req.Scopes, req.Public, backchannelLogoutURI)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "create failed")
		return
	}
	s.logAudit(r, ActionClientCreated, nil, &client.ID, logMeta("name", req.Name))
	resp := toClientView(client)
	if rawSecret != "" {
		resp["client_secret"] = rawSecret // shown once
	}
	s.writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleAdminGetClient(w http.ResponseWriter, r *http.Request) {
	client, ok := s.adminParseClient(w, r)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, toClientView(client))
}

func (s *Server) handleAdminDeleteClient(w http.ResponseWriter, r *http.Request) {
	client, ok := s.adminParseClient(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteClient(r.Context(), client.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "delete failed")
		return
	}
	s.logAudit(r, ActionClientDeleted, nil, &client.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminRotateClientSecret(w http.ResponseWriter, r *http.Request) {
	client, ok := s.adminParseClient(w, r)
	if !ok {
		return
	}
	if client.Public {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "public clients have no secret")
		return
	}
	rawSecret, err := auth.GenerateRawToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "generation failed")
		return
	}
	if err := s.store.UpdateClientSecret(r.Context(), client.ID, auth.HashToken(rawSecret)); err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "update failed")
		return
	}
	s.logAudit(r, ActionClientSecretRotated, nil, &client.ID, nil)
	s.writeJSON(w, http.StatusOK, map[string]string{
		"client_id":     client.ClientID,
		"client_secret": rawSecret,
	})
}

func (s *Server) adminParseClient(w http.ResponseWriter, r *http.Request) (*model.Client, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid client id")
		return nil, false
	}
	client, err := s.store.GetClientByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "not_found", "client not found")
		return nil, false
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "lookup failed")
		return nil, false
	}
	return client, true
}

// ── view helpers ──────────────────────────────────────────────────────────────

func toUserView(u *model.User) map[string]any {
	return map[string]any{
		"id":                  u.ID,
		"email":               u.Email,
		"name":                u.Name,
		"active":              u.Active,
		"mfa_enabled":         u.MFAEnabled,
		"scim_external_id":    u.SCIMExternalID,
		"password_changed_at": u.PasswordChangedAt,
		"created_at":          u.CreatedAt,
		"updated_at":          u.UpdatedAt,
	}
}

func toUserViews(users []*model.User) []map[string]any {
	out := make([]map[string]any, len(users))
	for i, u := range users {
		out[i] = toUserView(u)
	}
	return out
}

func toClientView(c *model.Client) map[string]any {
	out := map[string]any{
		"id":                c.ID,
		"client_id":         c.ClientID,
		"name":              c.Name,
		"redirect_uris":     c.RedirectURIs,
		"scopes":            c.Scopes,
		"public":            c.Public,
		"secret_rotated_at": c.SecretRotatedAt,
		"created_at":        c.CreatedAt,
	}
	if c.BackchannelLogoutURI != nil {
		out["backchannel_logout_uri"] = *c.BackchannelLogoutURI
	}
	return out
}

func toClientViews(clients []*model.Client) []map[string]any {
	out := make([]map[string]any, len(clients))
	for i, c := range clients {
		out[i] = toClientView(c)
	}
	return out
}
