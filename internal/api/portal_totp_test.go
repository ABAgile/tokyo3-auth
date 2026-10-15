package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestPortalTOTPEnroll_RedirectShowsQRCode follows the enroll redirect the
// way a browser does: the destination must exist and render the QR code
// from the pending-enrollment cookie set on the same response. The QR code
// must be an inline image so the TOTP secret never leaves this server.
func TestPortalTOTPEnroll_RedirectShowsQRCode(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "totp@example.com", "T0tpEnr0ll!Pass")
	cookie, _ := loginPortal(t, r, "totp@example.com", "T0tpEnr0ll!Pass")

	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/portal/mfa/totp/enroll", nil)
	resp := doRequest(t, req, cookie)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("enroll status = %d, want 302", resp.StatusCode)
	}

	next, _ := http.NewRequest(http.MethodGet, r.srv.URL+resp.Header.Get("Location"), nil)
	for _, c := range resp.Cookies() {
		if c.Name == portalTOTPCookie {
			next.AddCookie(c)
		}
	}
	page := doRequest(t, next, cookie)
	defer page.Body.Close()
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200", resp.Header.Get("Location"), page.StatusCode)
	}
	body, _ := io.ReadAll(page.Body)
	if !strings.Contains(string(body), "Scan this QR code") {
		t.Fatal("account page after enroll does not show the QR code")
	}
	if !strings.Contains(string(body), `src="data:image/png;base64,`) {
		t.Fatal("QR code is not an inline PNG data URI")
	}
}
