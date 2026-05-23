package api

import (
	"net/http"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/google/uuid"
)

// appTile is one entry on /portal/apps. The handler builds two kinds:
// "oidc" tiles back OAuth2 clients (LaunchURL is a normal HTTP link the
// browser navigates to directly — the RP starts its own SSO dance from
// there), and "aws" tiles back AWS federation roles (the user's click
// is a form-POST to /portal/aws/console, which does the AssumeRoleWithWebIdentity
// + getSigninToken + 302 dance auth-side). The template branches on Kind
// to render the right control.
type appTile struct {
	Kind         string // "oidc" or "aws"
	ID           string // client UUID or role UUID
	DisplayName  string
	Subtitle     string // optional second line — account alias for AWS, empty for OIDC
	LaunchURL    string // populated for "oidc"; empty for "aws" (form-POST handled in template)
	BrandColor   string
	IconURL      string
	StepUpMFA    bool // AWS roles flagged require_step_up_mfa render a badge
	TTLSeconds   int  // AWS roles only — surfaced as a small badge
	VisibleToAll bool // OIDC tiles: rendered with a small "everyone" hint for admin visibility
}

type appsPageData struct {
	portalBase
	Tiles []appTile
	Error string
}

// handlePortalApps is the unified /portal/apps entry point — aggregates
// every launchable target the user is authorized for. Tiles come from
// two sources: portal-visible OAuth2 clients (filtered by the user's
// SCIM groups via client_visibility or the visible_to_all shortcut) and
// AWS federation roles (existing ListAWSRolesForUser logic). The
// previous /portal/aws page is now a thin redirect to here so old
// bookmarks keep working.
func (s *Server) handlePortalApps(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	tiles := []appTile{}

	// OIDC client tiles
	clients, err := s.store.ListPortalClientsForUser(r.Context(), pc.User.ID)
	if err != nil {
		http.Error(w, "list portal clients: "+err.Error(), http.StatusInternalServerError)
		return
	}
	for _, c := range clients {
		if c.LaunchURL == "" {
			// Defensive: an operator marked show_in_portal=true without
			// setting a launch URL. The admin form validates this but a
			// SQL-direct insert could still produce it. Skip rather than
			// render a broken tile.
			continue
		}
		tiles = append(tiles, appTile{
			Kind:         "oidc",
			ID:           c.ID.String(),
			DisplayName:  c.Name,
			LaunchURL:    c.LaunchURL,
			BrandColor:   c.BrandColor,
			IconURL:      c.IconURL,
			VisibleToAll: c.VisibleToAll,
		})
	}

	// AWS federation tiles
	awsRoles, err := s.store.ListAWSRolesForUser(r.Context(), pc.User.ID)
	if err != nil {
		http.Error(w, "list aws roles: "+err.Error(), http.StatusInternalServerError)
		return
	}
	accounts, _ := s.store.ListAWSAccounts(r.Context())
	acctByID := make(map[uuid.UUID]*model.AWSAccount, len(accounts))
	for _, a := range accounts {
		acctByID[a.ID] = a
	}
	for _, role := range awsRoles {
		subtitle := ""
		if a := acctByID[role.AccountID]; a != nil {
			subtitle = "AWS · " + a.AccountID
			if a.Alias != "" {
				subtitle += " (" + a.Alias + ")"
			}
		} else {
			subtitle = "AWS"
		}
		tiles = append(tiles, appTile{
			Kind:        "aws",
			ID:          role.ID.String(),
			DisplayName: role.DisplayName,
			Subtitle:    subtitle,
			StepUpMFA:   role.RequireStepUpMFA,
			TTLSeconds:  role.MaxSessionDurationSec,
		})
	}

	s.portalTmpl.render(w, "portal_apps.html", appsPageData{
		portalBase: newPortalBase(pc, "apps"),
		Tiles:      tiles,
		Error:      r.URL.Query().Get("error"),
	})
}
