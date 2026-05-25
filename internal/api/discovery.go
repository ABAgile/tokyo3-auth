package api

import (
	"net/http"

	internaljwt "github.com/abagile/tokyo3-auth/internal/jwt"
)

// handleDiscovery serves the OIDC discovery document (RFC 8414).
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/authorize",
		"token_endpoint":                        s.issuer + "/token",
		"userinfo_endpoint":                     s.issuer + "/userinfo",
		"jwks_uri":                              s.issuer + "/.well-known/jwks.json",
		"revocation_endpoint":                   s.issuer + "/revoke",
		"device_authorization_endpoint":         s.issuer + "/device_authorization",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "preferred_username"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	s.writeJSON(w, http.StatusOK, doc)
}

// handleJWKS serves the JSON Web Key Set.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := internaljwt.BuildJWKS(r.Context(), s.store, s.kp)
	if err != nil {
		s.log.Error("build jwks", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "failed to build JWKS")
		return
	}
	s.writeJSON(w, http.StatusOK, jwks)
}
