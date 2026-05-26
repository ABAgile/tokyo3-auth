package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestFetchAWSCredentials_HappyPath exercises the AWS-specific wire
// shape: form-encoded role slug, bearer access token, JSON response
// in credential_process v1 format.
func TestFetchAWSCredentials_HappyPath(t *testing.T) {
	var (
		gotAuth string
		gotForm url.Values
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/aws/credentials" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		gotForm = r.PostForm
		_ = json.NewEncoder(w).Encode(awsCredentialsResponse{
			Version:         1,
			AccessKeyID:     "AKIA",
			SecretAccessKey: "secret",
			SessionToken:    "session",
			Expiration:      time.Now().Add(time.Hour).UTC(),
		})
	}))
	defer srv.Close()

	got, err := fetchAWSCredentials(srv.URL, "tok-access", "platform-prod")
	if err != nil {
		t.Fatalf("fetchAWSCredentials: %v", err)
	}
	if got.AccessKeyID != "AKIA" {
		t.Errorf("AccessKeyID = %q", got.AccessKeyID)
	}
	if gotAuth != "Bearer tok-access" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotForm.Get("role") != "platform-prod" {
		t.Errorf("role = %q", gotForm.Get("role"))
	}
}

// TestFetchAWSCredentials_NonOK_Surfaces propagates the status code
// and body so users see why STS exchange failed.
func TestFetchAWSCredentials_NonOK_Surfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "role 'nope' not configured", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := fetchAWSCredentials(srv.URL, "tok", "nope")
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "nope") {
		t.Errorf("err = %v, want 403 + body message", err)
	}
}
