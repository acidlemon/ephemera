package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSanitizeReturnTo(t *testing.T) {
	cases := []struct {
		inSub, inPath     string
		wantSub, wantPath string
	}{
		{"app", "/foo/bar", "app", "/foo/bar"},
		{"my-app1", "/", "my-app1", "/"},
		{"", "", "", "/"},
		{"evil.com/", "/", "", "/"},
		{"evil.com?", "/", "", "/"},
		{"evil.com#", "/", "", "/"},
		{"a.b", "/", "", "/"},
		{"-app", "/", "", "/"},
		{"app", "@evil.com", "app", "/"},
		{"app", "evil.com", "app", "/"},
		{"app", "/\\evil.com", "app", "/"},
		{"app", "/foo\r\nSet-Cookie: x=y", "app", "/"},
		{"app", "//evil.com", "app", "//evil.com"}, // ホストの後ろに付くのでパス扱いで安全
	}
	for _, c := range cases {
		sub, path := sanitizeReturnTo(c.inSub, c.inPath)
		if sub != c.wantSub || path != c.wantPath {
			t.Errorf("sanitizeReturnTo(%q, %q) = (%q, %q), want (%q, %q)", c.inSub, c.inPath, sub, path, c.wantSub, c.wantPath)
		}
	}
}

func TestCallbackAndVerifyWithoutSessionDoNotPanic(t *testing.T) {
	s := &Server{store: NewCookieStore("0123456789abcdef0123456789abcdef"), hostSuffix: "example.com", authSubdomain: "auth"}
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		req  *http.Request
	}{
		{"callback", s.CallbackAuth, httptest.NewRequest("GET", "https://auth.example.com/auth/callback", nil)},
		{"verify", s.VerifyAuth, httptest.NewRequest("POST", "https://auth.example.com/auth/verify", nil)},
	} {
		w := httptest.NewRecorder()
		tc.h(w, tc.req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", tc.name, w.Code)
		}
	}
}

func TestWriteHttpErrorHidesDetail(t *testing.T) {
	secret := "arn:aws:sts::123456789012:assumed-role/ephemera-role"
	for _, err := range []error{
		NewHttpError(http.StatusServiceUnavailable, "Failed to load configuration", errors.New(secret)),
		errors.New(secret),
	} {
		w := httptest.NewRecorder()
		WriteHttpError(w, err)
		body := w.Body.String()
		if strings.Contains(body, secret) {
			t.Errorf("error page leaks detail: %s", body)
		}
		if !strings.Contains(body, "Error ID") {
			t.Errorf("error page has no error id: %s", body)
		}
	}
}

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	h, err := NewServer(&ServerOptions{
		CookieStore:   NewCookieStore("0123456789abcdef0123456789abcdef"),
		ClientID:      "client",
		ClientSecret:  "secret",
		HostSuffix:    "example.com",
		AuthSubdomain: "auth",
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestStaticFilesAreServed(t *testing.T) {
	h := newTestServer(t)
	for _, p := range []string{"/auth/static/water.min.css", "/auth/static/ephemera.css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example.com"+p, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d", p, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
			t.Errorf("%s: Content-Type = %q", p, ct)
		}
		if cc := w.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "public") {
			t.Errorf("%s: Cache-Control = %q", p, cc)
		}
	}
}

func TestCallbackPageScriptIsAllowedByCSP(t *testing.T) {
	h := newTestServer(t)

	// /auth/start で認証セッションを作る
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example.com/auth/start?s=app&p=/", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("start: status = %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "https://accounts.google.com/") {
		t.Fatalf("start: Location = %q", loc)
	}

	req := httptest.NewRequest("GET", "https://auth.example.com/auth/callback", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("callback: status = %d", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src "+callbackScriptHash) {
		t.Errorf("CSP does not allow callback script: %q", csp)
	}
	if !strings.Contains(csp, "form-action 'self' https://accounts.google.com https://*.example.com") {
		t.Errorf("CSP form-action = %q", csp)
	}
	if !strings.Contains(w.Body.String(), "<script>"+callbackScript+"</script>") {
		t.Errorf("callback page does not embed callbackScript verbatim")
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestSignInPageHasNoInlineStyle(t *testing.T) {
	h := newTestServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example.com/auth/sign_in", nil))
	body := w.Body.String()
	if strings.Contains(body, "style=") || strings.Contains(body, "cdn.jsdelivr.net") {
		t.Errorf("sign-in page has inline style or CDN reference")
	}
	if !strings.Contains(body, `href="/auth/static/water.min.css"`) {
		t.Errorf("sign-in page does not link embedded css")
	}
}

func TestErrorPageOutsideAuthServerHasCSP(t *testing.T) {
	w := httptest.NewRecorder()
	WriteHttpError(w, NewHttpError(http.StatusServiceUnavailable, "Failed to load configuration", nil))
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'none'") {
		t.Errorf("CSP = %q", csp)
	}
}
