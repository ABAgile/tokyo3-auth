package api

import (
	"net/http"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/provision"
)

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
