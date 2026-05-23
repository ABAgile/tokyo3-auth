package main

import (
	"strings"
	"testing"
)

func TestSafeFilename(t *testing.T) {
	// Allowed character set is [A-Za-z0-9._-]; everything else becomes '_'.
	// Crucially the / character is replaced even when adjacent to dots,
	// which neutralises path-traversal payloads — without a slash, ".."
	// is just a filename segment, not a parent-directory escape.
	cases := map[string]string{
		"tokyo3-platform-prod":  "tokyo3-platform-prod",
		"with.dots":             "with.dots",
		"with/slash":            "with_slash",
		"../../../etc/passwd":   ".._.._.._etc_passwd",
		"a b c":                 "a_b_c",
		"":                      "default",
		"unicode-嗨":             "unicode-___",
		"shell$injection`echo`": "shell_injection_echo_",
	}
	for in, want := range cases {
		if got := safeFilename(in); got != want {
			t.Errorf("safeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSafeFilename_NoSlashesInResult is the load-bearing safety property:
// no input produces an output containing a path separator, so writes
// against `<cachedir>/<result>.json` cannot escape the cache directory.
func TestSafeFilename_NoSlashesInResult(t *testing.T) {
	for _, in := range []string{
		"../etc", "/etc/passwd", "..\\windows", "foo/bar/baz", "..\\..\\x",
	} {
		got := safeFilename(in)
		if strings.ContainsAny(got, "/\\") {
			t.Errorf("safeFilename(%q) = %q — contains path separator", in, got)
		}
	}
}

func TestBuildAuthorizeURL_PKCEAndScopes(t *testing.T) {
	url := buildAuthorizeURL("https://id.example.com", "tokyo3-cli",
		"http://127.0.0.1:54321/callback", "test-state", "test-challenge")
	// Brittle whole-string match would break on map-iteration order;
	// assert on individual query params instead.
	wants := []string{
		"https://id.example.com/authorize?",
		"client_id=tokyo3-cli",
		"response_type=code",
		"code_challenge=test-challenge",
		"code_challenge_method=S256",
		"state=test-state",
		"redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fcallback",
		"scope=openid+email+profile+offline_access",
	}
	for _, w := range wants {
		if !strings.Contains(url, w) {
			t.Errorf("buildAuthorizeURL missing %q in %s", w, url)
		}
	}
}

// TestBuildAuthorizeURL_TrailingSlashIssuer guards against double-slash
// in the authorize URL when the issuer is configured with a trailing
// slash (a common operator typo). The result should still produce one
// "/authorize?" with exactly one leading slash.
func TestBuildAuthorizeURL_TrailingSlashIssuer(t *testing.T) {
	url := buildAuthorizeURL("https://id.example.com/", "c", "http://x", "s", "ch")
	if strings.Contains(url, "//authorize") {
		t.Errorf("double-slash in authorize URL: %s", url)
	}
}
