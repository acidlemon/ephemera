package main

import (
	"net/http"
	"testing"

	"github.com/acidlemon/ephemera/auth"
)

func TestPrepareUpstreamRequest(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://app.example.com/", nil)
	req.Header.Add("Cookie", "ephemera_session=secret; app_sid=abc")
	req.Header.Add("Cookie", "ephemera_gate=g; theme=dark")
	req.Header.Set("X-Ephemera-Email", "attacker@example.com")
	req.Header.Set("X-Ephemera-Admin", "1")
	req.Header["X_Ephemera_Email"] = []string{"attacker@example.com"}
	req.Header["x-ephemera-sub"] = []string{"999"}

	prepareUpstreamRequest(req, &auth.LoginSession{Email: "user@example.com", Sub: "123"})

	if got := req.Header.Get("Cookie"); got != "app_sid=abc; theme=dark" {
		t.Errorf("Cookie = %q", got)
	}
	if got := req.Header.Get("X-Ephemera-Email"); got != "user@example.com" {
		t.Errorf("X-Ephemera-Email = %q", got)
	}
	if got := req.Header.Get("X-Ephemera-Sub"); got != "123" {
		t.Errorf("X-Ephemera-Sub = %q", got)
	}
	if got := req.Header.Get("X-Ephemera-Admin"); got != "" {
		t.Errorf("X-Ephemera-Admin should be removed, got %q", got)
	}
	for _, name := range []string{"X_Ephemera_Email", "x-ephemera-sub"} {
		if _, ok := req.Header[name]; ok {
			t.Errorf("%s should be removed", name)
		}
	}
}

func TestPrepareUpstreamRequestAnonymous(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://app.example.com/", nil)
	req.Header.Set("Cookie", "ephemera_session=secret")
	req.Header.Set("X-Ephemera-Email", "attacker@example.com")
	req.Header["X_EPHEMERA_EMAIL"] = []string{"attacker@example.com"}

	prepareUpstreamRequest(req, &auth.LoginSession{})

	if _, ok := req.Header["X_EPHEMERA_EMAIL"]; ok {
		t.Errorf("X_EPHEMERA_EMAIL should be removed")
	}

	if _, ok := req.Header["Cookie"]; ok {
		t.Errorf("Cookie header should be removed, got %q", req.Header.Get("Cookie"))
	}
	if got := req.Header.Get("X-Ephemera-Email"); got != "" {
		t.Errorf("X-Ephemera-Email should be removed, got %q", got)
	}
}
