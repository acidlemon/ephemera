package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

	prepareUpstreamRequest(req, &auth.LoginSession{Email: "user@example.com", Sub: "123", AuthMethod: auth.AuthMethodGoogle})

	if got := req.Header.Get("Cookie"); got != "app_sid=abc; theme=dark" {
		t.Errorf("Cookie = %q", got)
	}
	if got := req.Header.Get("X-Ephemera-Email"); got != "user@example.com" {
		t.Errorf("X-Ephemera-Email = %q", got)
	}
	if got := req.Header.Get("X-Ephemera-Sub"); got != "123" {
		t.Errorf("X-Ephemera-Sub = %q", got)
	}
	if got := req.Header.Get("X-Ephemera-Auth-Method"); got != "google" {
		t.Errorf("X-Ephemera-Auth-Method = %q", got)
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

func TestLoginForScopedSession(t *testing.T) {
	store = auth.NewCookieStore("0123456789abcdef0123456789abcdef")
	issue := func(values map[string]any) *http.Cookie {
		req, _ := http.NewRequest("GET", "https://auth.example.com/", nil)
		w := httptest.NewRecorder()
		sess, _ := store.New(req, "ephemera_session")
		for k, v := range values {
			sess.Values[k] = v
		}
		if err := sess.Save(req, w); err != nil {
			t.Fatal(err)
		}
		return w.Result().Cookies()[0]
	}
	valid := time.Now().Add(time.Hour).Unix()
	approval := issue(map[string]any{"email": "approver@example.com", "sub": "approval:ABCD-EFGH", "valid_until": valid,
		"auth_method": "approval", "allowed_subdomain": "app"})
	google := issue(map[string]any{"email": "approver@example.com", "sub": "123", "valid_until": valid, "auth_method": "google"})

	tests := []struct {
		name      string
		cookie    *http.Cookie
		subdomain string
		wantEmail string
	}{
		{"approval session on its subdomain", approval, "app", "approver@example.com"},
		{"approval session on another subdomain", approval, "other", ""},
		{"google session anywhere", google, "other", "approver@example.com"},
	}
	for _, tt := range tests {
		req, _ := http.NewRequest("GET", "https://"+tt.subdomain+".example.com/", nil)
		req.AddCookie(tt.cookie)
		login := loginFor(req, tt.subdomain)
		if login.Email != tt.wantEmail {
			t.Errorf("%s: email = %q, want %q", tt.name, login.Email, tt.wantEmail)
		}
		// ログインしていない扱いなら、バックエンドに身元のヘッダーを渡さない
		prepareUpstreamRequest(req, login)
		if got := req.Header.Get("X-Ephemera-Email"); got != tt.wantEmail {
			t.Errorf("%s: X-Ephemera-Email = %q", tt.name, got)
		}
	}
}
