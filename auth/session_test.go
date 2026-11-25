package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginSessionValidFor(t *testing.T) {
	tests := []struct {
		name      string
		session   LoginSession
		subdomain string
		want      bool
	}{
		{"google, any subdomain", LoginSession{Email: "a@example.com", AuthMethod: AuthMethodGoogle}, "app", true},
		{"approval, allowed subdomain", LoginSession{Email: "a@example.com", AuthMethod: AuthMethodApproval, AllowedSubdomain: "app"}, "app", true},
		{"approval, other subdomain", LoginSession{Email: "a@example.com", AuthMethod: AuthMethodApproval, AllowedSubdomain: "app"}, "other", false},
		{"not logged in", LoginSession{}, "app", false},
	}
	for _, tt := range tests {
		if got := tt.session.ValidFor(tt.subdomain); got != tt.want {
			t.Errorf("%s: ValidFor(%q) = %v, want %v", tt.name, tt.subdomain, got, tt.want)
		}
	}
}

// completeLogin で発行したセッションを ExtractSession で読み戻す
func issueSession(t *testing.T, s *Server, g loginGrant) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	s.completeLogin(w, httptest.NewRequest("POST", "https://auth.example.com/", nil), g, "app", "/")
	if w.Code != http.StatusFound {
		t.Fatalf("completeLogin status = %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == commonSessionName {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func extract(s *Server, c *http.Cookie) *LoginSession {
	req := httptest.NewRequest("GET", "https://app.example.com/", nil)
	req.AddCookie(c)
	return ExtractSession(req, s.store)
}

func TestCompleteLoginSessionRoundTrip(t *testing.T) {
	s := newTestServer(t).(*Server)

	google := extract(s, issueSession(t, s, loginGrant{Email: "a@example.com", Sub: "123", Method: AuthMethodGoogle, Validity: time.Hour}))
	if google.Email != "a@example.com" || google.AuthMethod != AuthMethodGoogle || google.AllowedSubdomain != "" {
		t.Errorf("google session = %+v", google)
	}
	if d := time.Until(google.ValidUntil); d < 59*time.Minute || d > time.Hour {
		t.Errorf("valid_until in %v", d)
	}

	approval := extract(s, issueSession(t, s, loginGrant{Email: "a@example.com", Sub: "approval:ABCD-EFGH", Method: AuthMethodApproval, Validity: time.Hour, AllowedSubdomain: "app"}))
	if approval.AuthMethod != AuthMethodApproval || approval.AllowedSubdomain != "app" || approval.Sub != "approval:ABCD-EFGH" {
		t.Errorf("approval session = %+v", approval)
	}

	// Google 以外でサブドメインに絞られていないセッションは使わない
	broken := extract(s, issueSession(t, s, loginGrant{Email: "a@example.com", Sub: "approval:X", Method: AuthMethodApproval, Validity: time.Hour}))
	if broken.Email != "" {
		t.Errorf("unscoped approval session must be rejected: %+v", broken)
	}
}

// 承認方式を入れる前に発行されたセッション（auth_method なし）は Google として扱う
func TestExtractSessionLegacy(t *testing.T) {
	s := newTestServer(t).(*Server)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://auth.example.com/", nil)
	sess, _ := s.store.New(req, commonSessionName)
	sess.Values["email"] = "a@example.com"
	sess.Values["sub"] = "123"
	sess.Values["valid_until"] = time.Now().Add(time.Hour).Unix()
	if err := sess.Save(req, w); err != nil {
		t.Fatal(err)
	}
	got := extract(s, w.Result().Cookies()[0])
	if got.AuthMethod != AuthMethodGoogle || got.AllowedSubdomain != "" || got.Email != "a@example.com" {
		t.Errorf("legacy session = %+v", got)
	}
}
