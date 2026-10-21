package main

import (
	"strings"
	"testing"
)

func TestAuthorizePageUsesPathnameAPIBase(t *testing.T) {
	if !strings.Contains(authorizeHTML, "const apiBase") {
		t.Fatal("authorize page must derive apiBase from location.pathname")
	}
	for _, bad := range []string{"api('/api/session", "api('/api/login", "api('/api/approve"} {
		if strings.Contains(authorizeHTML, bad) {
			t.Fatalf("host-root API call still present: %s", bad)
		}
	}
	for _, want := range []string{"api('/session?", "api('/login'", "api('/approve'"} {
		if !strings.Contains(authorizeHTML, want) {
			t.Fatalf("missing mount-aware API call: %s", want)
		}
	}
}
