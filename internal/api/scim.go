package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// ── SCIM helpers ──────────────────────────────────────────────────────────────

const (
	scimSchemaUser            = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimSchemaGroup           = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimSchemaListResponse    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimSchemaServiceProvider = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

func writeSCIMJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	writeSCIMJSON(w, status, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail,
		"status":  status,
	})
}

// ── SCIM resource types ───────────────────────────────────────────────────────

type scimMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created,omitzero"`
	LastModified time.Time `json:"lastModified,omitzero"`
	Location     string    `json:"location,omitempty"`
}

type scimNameAttr struct {
	Formatted string `json:"formatted,omitempty"`
}

type scimEmailAttr struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

type scimUserResource struct {
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id,omitempty"`
	ExternalID  string          `json:"externalId,omitempty"`
	UserName    string          `json:"userName"`
	Name        scimNameAttr    `json:"name,omitzero"`
	DisplayName string          `json:"displayName,omitempty"`
	Emails      []scimEmailAttr `json:"emails,omitempty"`
	Active      bool            `json:"active"`
	Meta        scimMeta        `json:"meta,omitzero"`
}

type scimMemberAttr struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

type scimGroupResource struct {
	Schemas     []string         `json:"schemas"`
	ID          string           `json:"id,omitempty"`
	DisplayName string           `json:"displayName"`
	Members     []scimMemberAttr `json:"members,omitempty"`
	Meta        scimMeta         `json:"meta,omitzero"`
}

type scimListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

type scimPatchOp struct {
	Schemas    []string `json:"schemas"`
	Operations []scimOp `json:"Operations"`
}

type scimOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ── converters ────────────────────────────────────────────────────────────────

func userToSCIM(u *model.User, issuer string) scimUserResource {
	return scimUserResource{
		Schemas:     []string{scimSchemaUser},
		ID:          u.ID.String(),
		ExternalID:  u.SCIMExternalID,
		UserName:    u.Email,
		Name:        scimNameAttr{Formatted: u.Name},
		DisplayName: u.Name,
		Emails:      []scimEmailAttr{{Value: u.Email, Primary: true, Type: "work"}},
		Active:      u.Active,
		Meta: scimMeta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
			Location:     issuer + "/scim/v2/Users/" + u.ID.String(),
		},
	}
}

func groupToSCIM(g *model.SCIMGroup, users map[uuid.UUID]*model.User, issuer string) scimGroupResource {
	members := make([]scimMemberAttr, 0, len(g.Members))
	for _, uid := range g.Members {
		m := scimMemberAttr{Value: uid.String()}
		if u, ok := users[uid]; ok {
			m.Display = u.Email
		}
		members = append(members, m)
	}
	return scimGroupResource{
		Schemas:     []string{scimSchemaGroup},
		ID:          g.ID.String(),
		DisplayName: g.DisplayName,
		Members:     members,
		Meta: scimMeta{
			ResourceType: "Group",
			Created:      g.CreatedAt,
			LastModified: g.UpdatedAt,
			Location:     issuer + "/scim/v2/Groups/" + g.ID.String(),
		},
	}
}

// userMap builds a id→User lookup from a list.
func (s *Server) userMap(r *http.Request) map[uuid.UUID]*model.User {
	all, _ := s.store.ListUsers(r.Context())
	m := make(map[uuid.UUID]*model.User, len(all))
	for _, u := range all {
		m[u.ID] = u
	}
	return m
}

// ── ServiceProviderConfig ─────────────────────────────────────────────────────

func (s *Server) handleSCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":               []string{scimSchemaServiceProvider},
		"documentationUri":      s.issuer,
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": false, "maxResults": 200},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{{"type": "oauthbearertoken", "name": "OAuth Bearer Token"}},
	})
}

// ── Schemas ───────────────────────────────────────────────────────────────────

func (s *Server) handleSCIMSchemas(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimSchemaListResponse},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources": []map[string]any{
			{"id": scimSchemaUser, "name": "User", "description": "User Account"},
			{"id": scimSchemaGroup, "name": "Group", "description": "Group"},
		},
	})
}

// ── Users ─────────────────────────────────────────────────────────────────────

func (s *Server) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "list failed")
		return
	}
	resources := make([]any, len(users))
	for i, u := range users {
		resources[i] = userToSCIM(u, s.issuer)
	}
	writeSCIMJSON(w, http.StatusOK, scimListResponse{
		Schemas:      []string{scimSchemaListResponse},
		TotalResults: len(users),
		StartIndex:   1,
		ItemsPerPage: len(users),
		Resources:    resources,
	})
}

func (s *Server) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	var req scimUserResource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.UserName))
	if email == "" {
		writeSCIMError(w, http.StatusBadRequest, "userName is required")
		return
	}
	name := req.DisplayName
	if name == "" {
		name = req.Name.Formatted
	}
	if name == "" {
		name = email
	}
	// SCIM provisioners don't supply passwords; set a random unusable hash.
	ph := "*scim-provisioned*"
	user, err := s.store.CreateUser(r.Context(), email, ph, name)
	if errors.Is(err, store.ErrConflict) {
		writeSCIMError(w, http.StatusConflict, "user already exists")
		return
	}
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "create failed")
		return
	}
	if req.ExternalID != "" {
		_ = s.store.SetUserSCIMExternalID(r.Context(), user.ID, req.ExternalID)
		user.SCIMExternalID = req.ExternalID
	}
	if !req.Active {
		_ = s.store.SetUserActive(r.Context(), user.ID, false)
		user.Active = false
	}
	s.logAudit(r, ActionSCIMUserCreated, &user.ID, nil, logMeta("email", email))
	s.provisionUser(r, provision.OpCreate, user, nil)
	w.Header().Set("Location", s.issuer+"/scim/v2/Users/"+user.ID.String())
	writeSCIMJSON(w, http.StatusCreated, userToSCIM(user, s.issuer))
}

func (s *Server) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid id")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeSCIMJSON(w, http.StatusOK, userToSCIM(user, s.issuer))
}

func (s *Server) handleSCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req scimUserResource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	name := req.DisplayName
	if name == "" {
		name = req.Name.Formatted
	}
	if name == "" {
		name = user.Name
	}
	_ = s.store.UpdateUser(r.Context(), id, name, req.Active)
	if req.ExternalID != "" {
		_ = s.store.SetUserSCIMExternalID(r.Context(), id, req.ExternalID)
	}
	user, _ = s.store.GetUserByID(r.Context(), id)
	s.logAudit(r, ActionSCIMUserUpdated, &id, nil, logMeta("active", req.Active))
	if req.Active {
		s.provisionUser(r, provision.OpUpdate, user, nil)
	} else {
		s.provisionUser(r, provision.OpDeactivate, user, nil)
	}
	writeSCIMJSON(w, http.StatusOK, userToSCIM(user, s.issuer))
}

func (s *Server) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid id")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	var patch scimPatchOp
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	for _, op := range patch.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			s.applyUserPatchReplace(r, user, op)
		}
	}
	user, _ = s.store.GetUserByID(r.Context(), id)
	s.logAudit(r, ActionSCIMUserUpdated, &id, nil, nil)
	writeSCIMJSON(w, http.StatusOK, userToSCIM(user, s.issuer))
}

func (s *Server) applyUserPatchReplace(r *http.Request, user *model.User, op scimOp) {
	path := strings.ToLower(op.Path)
	switch path {
	case "active":
		var active bool
		if err := json.Unmarshal(op.Value, &active); err == nil {
			_ = s.store.SetUserActive(r.Context(), user.ID, active)
			if active {
				s.provisionUser(r, provision.OpUpdate, user, nil)
			} else {
				s.provisionUser(r, provision.OpDeactivate, user, nil)
			}
		}
	case "displayname", "name.formatted":
		var name string
		if err := json.Unmarshal(op.Value, &name); err == nil && name != "" {
			_ = s.store.UpdateUser(r.Context(), user.ID, name, user.Active)
		}
	case "":
		// Bulk replace: value may be a map of attribute→value
		var attrs map[string]json.RawMessage
		if err := json.Unmarshal(op.Value, &attrs); err == nil {
			if v, ok := attrs["active"]; ok {
				var active bool
				if err := json.Unmarshal(v, &active); err == nil {
					_ = s.store.SetUserActive(r.Context(), user.ID, active)
				}
			}
		}
	}
}

func (s *Server) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid id")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	_ = s.store.DeleteSessionsByUserID(r.Context(), id)
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.logAudit(r, ActionSCIMUserDeleted, &id, nil, nil)
	s.provisionUser(r, provision.OpDelete, user, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ── Groups ────────────────────────────────────────────────────────────────────

func (s *Server) handleSCIMListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "list failed")
		return
	}
	um := s.userMap(r)
	resources := make([]any, len(groups))
	for i, g := range groups {
		resources[i] = groupToSCIM(g, um, s.issuer)
	}
	writeSCIMJSON(w, http.StatusOK, scimListResponse{
		Schemas:      []string{scimSchemaListResponse},
		TotalResults: len(groups),
		StartIndex:   1,
		ItemsPerPage: len(groups),
		Resources:    resources,
	})
}

func (s *Server) handleSCIMCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req scimGroupResource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.DisplayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "displayName is required")
		return
	}
	g, err := s.store.CreateGroup(r.Context(), req.DisplayName)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "create failed")
		return
	}
	if len(req.Members) > 0 {
		ids := parseScimMemberIDs(req.Members)
		_ = s.store.ReplaceGroupMembers(r.Context(), g.ID, ids)
		g.Members = ids
	}
	s.logAudit(r, ActionSCIMGroupCreated, nil, nil, logMeta("name", req.DisplayName))
	s.provisionGroup(r, provision.OpCreate, g, nil)
	um := s.userMap(r)
	w.Header().Set("Location", s.issuer+"/scim/v2/Groups/"+g.ID.String())
	writeSCIMJSON(w, http.StatusCreated, groupToSCIM(g, um, s.issuer))
}

func (s *Server) handleSCIMGetGroup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid id")
		return
	}
	g, err := s.store.GetGroupByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "group not found")
		return
	}
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeSCIMJSON(w, http.StatusOK, groupToSCIM(g, s.userMap(r), s.issuer))
}

func (s *Server) handleSCIMReplaceGroup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req scimGroupResource
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	g, err := s.store.GetGroupByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "group not found")
		return
	}
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if req.DisplayName != "" && req.DisplayName != g.DisplayName {
		_ = s.store.UpdateGroup(r.Context(), id, req.DisplayName)
	}
	ids := parseScimMemberIDs(req.Members)
	_ = s.store.ReplaceGroupMembers(r.Context(), id, ids)
	g, _ = s.store.GetGroupByID(r.Context(), id)
	s.logAudit(r, ActionSCIMGroupUpdated, nil, nil, logMeta("group_id", id))
	writeSCIMJSON(w, http.StatusOK, groupToSCIM(g, s.userMap(r), s.issuer))
}

func (s *Server) handleSCIMPatchGroup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid id")
		return
	}
	g, err := s.store.GetGroupByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "group not found")
		return
	}
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	var patch scimPatchOp
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	for _, op := range patch.Operations {
		s.applyGroupOp(r, g.ID, op)
	}
	g, _ = s.store.GetGroupByID(r.Context(), id)
	s.logAudit(r, ActionSCIMGroupUpdated, nil, nil, logMeta("group_id", id))
	writeSCIMJSON(w, http.StatusOK, groupToSCIM(g, s.userMap(r), s.issuer))
}

func (s *Server) applyGroupOp(r *http.Request, groupID uuid.UUID, op scimOp) {
	path := strings.ToLower(op.Path)
	switch strings.ToLower(op.Op) {
	case "add":
		if path == "members" || path == "" {
			ids := parseMemberValue(op.Value)
			for _, uid := range ids {
				_ = s.store.AddGroupMember(r.Context(), groupID, uid)
			}
		}
	case "remove":
		if path == "members" || path == "" {
			ids := parseMemberValue(op.Value)
			for _, uid := range ids {
				_ = s.store.RemoveGroupMember(r.Context(), groupID, uid)
			}
		}
	case "replace":
		switch path {
		case "members", "":
			ids := parseMemberValue(op.Value)
			_ = s.store.ReplaceGroupMembers(r.Context(), groupID, ids)
		case "displayname":
			var name string
			if err := json.Unmarshal(op.Value, &name); err == nil && name != "" {
				_ = s.store.UpdateGroup(r.Context(), groupID, name)
			}
		}
	}
}

func (s *Server) handleSCIMDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := s.store.GetGroupByID(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeSCIMError(w, http.StatusNotFound, "group not found")
		return
	}
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	s.logAudit(r, ActionSCIMGroupDeleted, nil, nil, logMeta("group_id", id))
	w.WriteHeader(http.StatusNoContent)
}

// ── Provisioner fan-out ───────────────────────────────────────────────────────

// provisionUser fans out a user lifecycle event to every registered downstream
// provisioner (AWS IAM, vault SCIM, etc.). Errors are logged inside Set; the
// originating request is never blocked by a downstream failure.
func (s *Server) provisionUser(r *http.Request, op provision.Op, user *model.User, groups []string) {
	s.provReg.User(r.Context(), op, user, groups)
}

// provisionGroup fans out a group lifecycle event to every provisioner.
func (s *Server) provisionGroup(r *http.Request, op provision.Op, g *model.SCIMGroup, members []*model.User) {
	s.provReg.Group(r.Context(), op, g, members)
}

// ── member parsing helpers ────────────────────────────────────────────────────

func parseScimMemberIDs(members []scimMemberAttr) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		if id, err := uuid.Parse(m.Value); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// parseMemberValue decodes the SCIM patch "value" for members operations.
// It handles both array-of-objects and bare-object forms.
func parseMemberValue(raw json.RawMessage) []uuid.UUID {
	if len(raw) == 0 {
		return nil
	}
	// Try array form: [{"value": "uuid"}, ...]
	var arr []scimMemberAttr
	if err := json.Unmarshal(raw, &arr); err == nil {
		return parseScimMemberIDs(arr)
	}
	// Try single object
	var single scimMemberAttr
	if err := json.Unmarshal(raw, &single); err == nil && single.Value != "" {
		if id, err := uuid.Parse(single.Value); err == nil {
			return []uuid.UUID{id}
		}
	}
	return nil
}
