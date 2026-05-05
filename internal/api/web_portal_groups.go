package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// pickUsers returns the subset of users whose IDs appear in ids, preserving
// ids order. Unknown ids are silently dropped — the form-side checkbox list
// already constrains submissions to known users.
func pickUsers(users []*model.User, ids []uuid.UUID) []*model.User {
	if len(ids) == 0 {
		return nil
	}
	byID := make(map[uuid.UUID]*model.User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	out := make([]*model.User, 0, len(ids))
	for _, id := range ids {
		if u, ok := byID[id]; ok {
			out = append(out, u)
		}
	}
	return out
}

// groupView decorates a SCIMGroup with a precomputed member count for the list page.
type groupView struct {
	Group   *model.SCIMGroup
	Members int
}

func (s *Server) handlePortalAdminGroups(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		http.Error(w, "error listing groups", http.StatusInternalServerError)
		return
	}
	views := make([]groupView, len(groups))
	for i, g := range groups {
		views[i] = groupView{Group: g, Members: len(g.Members)}
	}
	s.portalTmpl.render(w, "portal_admin_groups.html", struct {
		portalBase
		Groups         []groupView
		Success, Error string
	}{newPortalBase(pc, "admin-groups"), views, r.URL.Query().Get("success"), r.URL.Query().Get("error")})
}

func (s *Server) handlePortalAdminGroupNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)

	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "list users failed", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		s.renderGroupForm(w, pc, &model.SCIMGroup{}, users, true, "", nil)
		return
	}

	_ = r.ParseForm()
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	memberIDs := parseMemberIDs(r.Form["members"])

	if displayName == "" {
		s.renderGroupForm(w, pc, &model.SCIMGroup{DisplayName: displayName, Members: memberIDs}, users, true, "Display name is required.", memberIDs)
		return
	}

	g, err := s.store.CreateGroup(r.Context(), displayName)
	if err != nil {
		s.log.Error("create group", "err", err)
		s.renderGroupForm(w, pc, &model.SCIMGroup{DisplayName: displayName, Members: memberIDs}, users, true, "Create failed.", memberIDs)
		return
	}
	if len(memberIDs) > 0 {
		if err := s.store.ReplaceGroupMembers(r.Context(), g.ID, memberIDs); err != nil {
			s.log.Error("set group members", "err", err)
		}
	}
	s.logAudit(r, ActionGroupCreated, &pc.User.ID, nil,
		logMeta("name", displayName, "members", len(memberIDs)))

	g.Members = memberIDs
	s.provisionGroup(r, provision.OpCreate, g, pickUsers(users, memberIDs))

	http.Redirect(w, r, "/portal/admin/groups?success=Group+created.", http.StatusFound)
}

func (s *Server) handlePortalAdminGroupEdit(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	g, err := s.store.GetGroupByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "list users failed", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		s.renderGroupForm(w, pc, g, users, false, "", g.Members)
		return
	}

	_ = r.ParseForm()
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	memberIDs := parseMemberIDs(r.Form["members"])

	if displayName == "" {
		g.DisplayName = displayName
		s.renderGroupForm(w, pc, g, users, false, "Display name is required.", memberIDs)
		return
	}

	if err := s.store.UpdateGroup(r.Context(), id, displayName); err != nil {
		s.log.Error("update group", "err", err)
		s.renderGroupForm(w, pc, g, users, false, "Update failed.", memberIDs)
		return
	}
	if err := s.store.ReplaceGroupMembers(r.Context(), id, memberIDs); err != nil {
		s.log.Error("replace group members", "err", err)
	}
	s.logAudit(r, ActionGroupUpdated, &pc.User.ID, nil,
		logMeta("name", displayName, "members", len(memberIDs)))

	g.DisplayName = displayName
	g.Members = memberIDs
	s.provisionGroup(r, provision.OpUpdate, g, pickUsers(users, memberIDs))

	http.Redirect(w, r, "/portal/admin/groups?success=Group+updated.", http.StatusFound)
}

func (s *Server) handlePortalAdminGroupDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	g, err := s.store.GetGroupByID(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/portal/admin/groups?error=group+not+found", http.StatusFound)
		return
	}
	if err := s.store.DeleteGroup(r.Context(), id); err != nil {
		http.Redirect(w, r, "/portal/admin/groups?error=delete+failed", http.StatusFound)
		return
	}
	s.logAudit(r, ActionGroupDeleted, &pc.User.ID, nil,
		logMeta("name", g.DisplayName))
	s.provisionGroup(r, provision.OpDelete, g, nil)
	http.Redirect(w, r, "/portal/admin/groups?success=Group+deleted.", http.StatusFound)
}

// ── helpers ───────────────────────────────────────────────────────────────────

type groupFormView struct {
	portalBase
	Group *model.SCIMGroup
	Users []userMembership
	IsNew bool
	Error string
}

type userMembership struct {
	User     *model.User
	IsMember bool
}

func (s *Server) renderGroupForm(w http.ResponseWriter, pc *portalCtx, g *model.SCIMGroup, users []*model.User, isNew bool, errMsg string, selected []uuid.UUID) {
	selSet := make(map[uuid.UUID]struct{}, len(selected))
	for _, id := range selected {
		selSet[id] = struct{}{}
	}
	views := make([]userMembership, len(users))
	for i, u := range users {
		_, in := selSet[u.ID]
		views[i] = userMembership{User: u, IsMember: in}
	}
	s.portalTmpl.render(w, "portal_admin_group_edit.html", groupFormView{
		portalBase: newPortalBase(pc, "admin-groups"),
		Group:      g,
		Users:      views,
		IsNew:      isNew,
		Error:      errMsg,
	})
}

func parseMemberIDs(raw []string) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if id, err := uuid.Parse(s); err == nil {
			out = append(out, id)
		}
	}
	return out
}

