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
