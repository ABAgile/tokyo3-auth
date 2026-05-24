package main

import (
	"strings"
	"testing"
)

// TestValidateNewUserPassword exercises the CLI's password gate. The
// gate is what prevents `authd admin user create --email x --password
// password` from silently slipping a weak credential into the database;
// the regression we're guarding against is forgetting to check policy
// on the programmatic creation path.
func TestValidateNewUserPassword(t *testing.T) {
	cases := []struct {
		name    string
		pw      string
		allow   bool
		wantErr bool
	}{
		{name: "weak rejected by default", pw: "password", allow: false, wantErr: true},
		{name: "short rejected by default", pw: "Ab1!", allow: false, wantErr: true},
		{name: "strong accepted", pw: "FullyC0mpliant!Pass", allow: false, wantErr: false},
		{name: "weak bypassed with allowWeak", pw: "password", allow: true, wantErr: false},
		{name: "empty bypassed with allowWeak", pw: "", allow: true, wantErr: false},
		// The PCI engine doesn't have a "non-empty" rule, so an empty
		// password actually trips a different rule (length). Worth
		// asserting so a future engine refactor doesn't silently make
		// "" pass the default-rule set.
		{name: "empty rejected by default", pw: "", allow: false, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNewUserPassword(tc.pw, tc.allow)
			if tc.wantErr && err == nil {
				t.Errorf("validateNewUserPassword(%q, allow=%v) = nil, want error", tc.pw, tc.allow)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateNewUserPassword(%q, allow=%v) = %v, want nil", tc.pw, tc.allow, err)
			}
		})
	}
}

// TestValidateNewUserPassword_ErrorMentionsBypass guards the operator
// hint — when a password is rejected, the error string should tell them
// HOW to override it (the --allow-weak-password flag). Without that
// guidance, an operator hitting the failure for the first time may not
// know the bypass exists; the help text is on the wrong screen for an
// error they're seeing in their terminal.
func TestValidateNewUserPassword_ErrorMentionsBypass(t *testing.T) {
	err := validateNewUserPassword("weak", false)
	if err == nil {
		t.Fatal("expected error for weak password")
	}
	if !strings.Contains(err.Error(), "--allow-weak-password") {
		t.Errorf("error %q should mention --allow-weak-password as the bypass mechanism", err)
	}
}
