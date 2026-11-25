package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var approvalAuthorities = map[string][]string{
	"approver@example.com": {"app"},
	"admin@example.com":    {"*"},
	"other@example.com":    {"other"},
}

type approvalEnv struct {
	t     *testing.T
	h     http.Handler
	s     *Server
	store *memoryApprovalStore
}

func newApprovalEnv(t *testing.T) *approvalEnv {
	t.Helper()
	store := newMemoryApprovalStore()
	h, err := NewServer(&ServerOptions{
		CookieStore:   NewCookieStore("0123456789abcdef0123456789abcdef"),
		ClientID:      "client",
		ClientSecret:  "secret",
		HostSuffix:    "example.com",
		AuthSubdomain: "auth",
		ApprovalStore: store,
		Authorities:   approvalAuthorities,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &approvalEnv{t: t, h: h, s: h.(*Server), store: store}
}

func (e *approvalEnv) do(method, target string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, "https://auth.example.com"+target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, "https://auth.example.com"+target, nil)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

// start は承認の要求を作り、申請者のブラウザの cookie とコードを返す
func (e *approvalEnv) start(subdomain, path string) (*http.Cookie, string) {
	e.t.Helper()
	w := e.do("POST", "/auth/approval/start", url.Values{"s": {subdomain}, "p": {path}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/auth/approval/wait" {
		e.t.Fatalf("start: status = %d, location = %q", w.Code, w.Header().Get("Location"))
	}
	c := findCookie(w, approvalCookieName)
	if c == nil || c.SameSite != http.SameSiteStrictMode || !c.HttpOnly || !c.Secure || c.Path != approvalCookiePath {
		e.t.Fatalf("approval cookie = %+v", c)
	}
	code, _, _ := strings.Cut(c.Value, ".")
	return c, code
}

func (e *approvalEnv) googleSession(email string) *http.Cookie {
	e.t.Helper()
	return issueSession(e.t, e.s, loginGrant{Email: email, Sub: "google-" + email, Method: AuthMethodGoogle, Validity: time.Hour})
}

func (e *approvalEnv) decide(approver *http.Cookie, code, action string) *httptest.ResponseRecorder {
	return e.do("POST", "/auth/approval/decide", url.Values{"code": {code}, "action": {action}}, approver)
}

func (e *approvalEnv) status(code string) string {
	r, _, err := e.store.Get(context.Background(), code)
	if err != nil {
		e.t.Fatal(err)
	}
	return r.Status
}

func TestApprovalFlow(t *testing.T) {
	e := newApprovalEnv(t)
	requester, code := e.start("app", "/foo")

	// 待ち画面: コードを表示し、自動で更新する
	w := e.do("GET", "/auth/approval/wait", nil, requester)
	if w.Code != http.StatusOK || w.Header().Get("Refresh") == "" || !strings.Contains(w.Body.String(), code) {
		t.Fatalf("wait: status = %d, refresh = %q", w.Code, w.Header().Get("Refresh"))
	}
	// 承認ページへのリンク（コード付き）を右クリックでコピーできる
	if link := `href="https://auth.example.com/auth/approval?code=` + code + `"`; !strings.Contains(w.Body.String(), link) {
		t.Errorf("wait page has no approval link: %s", link)
	}
	// コピーボタンと、それを動かすスクリプト（CSP の script-src 'self' で許可）
	if !strings.Contains(w.Body.String(), `data-copy="`+code+`"`) || !strings.Contains(w.Body.String(), `src="/auth/static/copy.js"`) {
		t.Errorf("wait page has no copy buttons")
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self' ") {
		t.Errorf("CSP does not allow /auth/static scripts: %q", csp)
	}

	// 承認者がコードを入力すると中身が出る（小文字・ハイフンなしでもよい）
	approver := e.googleSession("approver@example.com")
	w = e.do("GET", "/auth/approval?code="+strings.ToLower(strings.ReplaceAll(code, "-", "")), nil, approver)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "https://app.example.com/foo") ||
		!strings.Contains(w.Body.String(), `value="approve"`) {
		t.Fatalf("lookup: status = %d", w.Code)
	}

	if w := e.decide(approver, code, "approve"); w.Code != http.StatusOK {
		t.Fatalf("approve: status = %d", w.Code)
	}
	if got := e.status(code); got != ApprovalApproved {
		t.Fatalf("status = %q", got)
	}

	// 申請者の待ち画面がセッションを受け取る
	w = e.do("GET", "/auth/approval/wait", nil, requester)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://app.example.com/foo" {
		t.Fatalf("wait after approval: status = %d, location = %q", w.Code, w.Header().Get("Location"))
	}
	if c := findCookie(w, approvalCookieName); c == nil || c.MaxAge >= 0 {
		t.Errorf("approval cookie is not deleted: %+v", c)
	}
	session := extract(e.s, findCookie(w, commonSessionName))
	if session.Email != "approver@example.com" || session.AuthMethod != AuthMethodApproval ||
		session.AllowedSubdomain != "app" || session.Sub != "approval:"+code {
		t.Errorf("session = %+v", session)
	}
	if d := time.Until(session.ValidUntil); d < approvalLoginValidity-time.Minute || d > approvalLoginValidity {
		t.Errorf("valid_until in %v", d)
	}
	if !session.ValidFor("app") || session.ValidFor("other") {
		t.Errorf("session scope is wrong: %+v", session)
	}
	if got := e.status(code); got != ApprovalConsumed {
		t.Errorf("status after login = %q", got)
	}

	// 同じ要求では二度とセッションを受け取れない
	if w := e.do("GET", "/auth/approval/wait", nil, requester); w.Code == http.StatusFound {
		t.Errorf("request reused")
	}
}

func TestApprovalDeny(t *testing.T) {
	e := newApprovalEnv(t)
	requester, code := e.start("app", "/")
	if w := e.decide(e.googleSession("approver@example.com"), code, "deny"); w.Code != http.StatusOK {
		t.Fatalf("deny: status = %d", w.Code)
	}
	w := e.do("GET", "/auth/approval/wait", nil, requester)
	if w.Code != http.StatusForbidden || findCookie(w, commonSessionName) != nil {
		t.Errorf("wait after deny: status = %d", w.Code)
	}
}

func TestApprovalWhoCanApprove(t *testing.T) {
	tests := []struct {
		name     string
		approver *http.Cookie
		wantCode int
	}{
		{"allowed for the subdomain", nil, http.StatusOK}, // approver（下で設定）
		{"wildcard", nil, http.StatusOK},                  // admin
		{"other subdomain only", nil, http.StatusNotFound},
		{"not in authorities", nil, http.StatusNotFound},
	}
	emails := []string{"approver@example.com", "admin@example.com", "other@example.com", "nobody@example.com"}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newApprovalEnv(t)
			_, code := e.start("app", "/")
			approver := e.googleSession(emails[i])
			if w := e.do("GET", "/auth/approval?code="+code, nil, approver); w.Code != tt.wantCode {
				t.Errorf("lookup: status = %d, want %d", w.Code, tt.wantCode)
			}
			if w := e.decide(approver, code, "approve"); w.Code != tt.wantCode {
				t.Errorf("decide: status = %d, want %d", w.Code, tt.wantCode)
			}
			want := ApprovalPending
			if tt.wantCode == http.StatusOK {
				want = ApprovalApproved
			}
			if got := e.status(code); got != want {
				t.Errorf("status = %q, want %q", got, want)
			}
		})
	}
}

func TestApprovalPageRequiresGoogleLogin(t *testing.T) {
	e := newApprovalEnv(t)
	_, code := e.start("app", "/")

	// ログインしていなければ Google のログインへ
	w := e.do("GET", "/auth/approval", nil)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/auth/start?p=/auth/approval" {
		t.Errorf("not logged in: status = %d, location = %q", w.Code, w.Header().Get("Location"))
	}

	// 承認方式で入ったセッションでは承認できない（承認の連鎖を防ぐ）
	approvalSession := issueSession(t, e.s, loginGrant{Email: "approver@example.com", Sub: "approval:X", Method: AuthMethodApproval, Validity: time.Hour, AllowedSubdomain: "app"})
	if w := e.do("GET", "/auth/approval?code="+code, nil, approvalSession); w.Code != http.StatusForbidden {
		t.Errorf("approval session lookup: status = %d", w.Code)
	}
	if w := e.decide(approvalSession, code, "approve"); w.Code != http.StatusForbidden {
		t.Errorf("approval session decide: status = %d", w.Code)
	}
	if w := e.decide(nil, code, "approve"); w.Code != http.StatusForbidden {
		t.Errorf("anonymous decide: status = %d", w.Code)
	}
	if got := e.status(code); got != ApprovalPending {
		t.Errorf("status = %q", got)
	}
}

func TestApprovalWaitRequiresSecret(t *testing.T) {
	e := newApprovalEnv(t)
	requester, code := e.start("app", "/")
	e.decide(e.googleSession("approver@example.com"), code, "approve")

	forged := &http.Cookie{Name: approvalCookieName, Value: code + ".wrong-secret"}
	if w := e.do("GET", "/auth/approval/wait", nil, forged); w.Code != http.StatusForbidden || findCookie(w, commonSessionName) != nil {
		t.Errorf("forged secret: status = %d", w.Code)
	}
	if w := e.do("GET", "/auth/approval/wait", nil); w.Code != http.StatusForbidden {
		t.Errorf("no cookie: status = %d", w.Code)
	}
	// 本物の cookie ならまだ受け取れる
	if w := e.do("GET", "/auth/approval/wait", nil, requester); w.Code != http.StatusFound {
		t.Errorf("real cookie after forged attempts: status = %d", w.Code)
	}
}

func TestApprovalApproverLostAccess(t *testing.T) {
	e := newApprovalEnv(t)
	requester, code := e.start("app", "/")
	e.decide(e.googleSession("approver@example.com"), code, "approve")
	// 承認のあとで承認者が authorities.json から外された
	e.s.authorities = map[string][]string{"admin@example.com": {"*"}}
	w := e.do("GET", "/auth/approval/wait", nil, requester)
	if w.Code != http.StatusForbidden || findCookie(w, commonSessionName) != nil {
		t.Errorf("status = %d", w.Code)
	}
}

func TestApprovalExpired(t *testing.T) {
	e := newApprovalEnv(t)
	requester, code := e.start("app", "/")
	r, etag, _ := e.store.Get(context.Background(), code)
	r.ExpiresAt = time.Now().Add(-time.Second)
	if err := e.store.Update(context.Background(), r, etag); err != nil {
		t.Fatal(err)
	}
	approver := e.googleSession("approver@example.com")
	if w := e.decide(approver, code, "approve"); w.Code != http.StatusNotFound {
		t.Errorf("approve expired: status = %d", w.Code)
	}
	if w := e.do("GET", "/auth/approval/wait", nil, requester); w.Code != http.StatusForbidden {
		t.Errorf("wait expired: status = %d", w.Code)
	}
}

func TestApprovalStartRejects(t *testing.T) {
	e := newApprovalEnv(t)
	if w := e.do("POST", "/auth/approval/start", url.Values{"s": {""}, "p": {"/"}}); w.Code != http.StatusBadRequest {
		t.Errorf("no destination: status = %d", w.Code)
	}
	if w := e.do("GET", "/auth/approval/start", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d", w.Code)
	}
	for _, h := range []struct{ k, v string }{{"Sec-Fetch-Site", "cross-site"}, {"Origin", "https://evil.example.net"}} {
		req := httptest.NewRequest("POST", "https://auth.example.com/auth/approval/start", strings.NewReader("s=app&p=/"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(h.k, h.v)
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s=%s: status = %d", h.k, h.v, w.Code)
		}
	}
	// 承認の決定も別サイトからは受け付けない
	_, code := e.start("app", "/")
	req := httptest.NewRequest("POST", "https://auth.example.com/auth/approval/decide", strings.NewReader("action=approve&code="+code))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(e.googleSession("approver@example.com"))
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || e.status(code) != ApprovalPending {
		t.Errorf("cross-site decide: status = %d", w.Code)
	}
}

func TestApprovalDisabled(t *testing.T) {
	h := newTestServer(t)
	for _, p := range []string{"/auth/approval", "/auth/approval/start", "/auth/approval/wait", "/auth/approval/decide"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "https://auth.example.com"+p, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d", p, w.Code)
		}
	}
}

func TestSignInPageApprovalForm(t *testing.T) {
	signIn := func(h http.Handler, s *Server, subdomain string) string {
		req := httptest.NewRequest("GET", "https://auth.example.com/auth/sign_in", nil)
		if subdomain != "" {
			w := httptest.NewRecorder()
			gate, _ := s.store.New(req, "ephemera_gate")
			gate.Values["subdomain"] = subdomain
			gate.Values["path"] = "/"
			gate.Save(req, w)
			req.AddCookie(w.Result().Cookies()[0])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Body.String()
	}
	e := newApprovalEnv(t)
	if !strings.Contains(signIn(e.h, e.s, "app"), `action="/auth/approval/start"`) {
		t.Errorf("approval form is not shown")
	}
	if strings.Contains(signIn(e.h, e.s, ""), `action="/auth/approval/start"`) {
		t.Errorf("approval form is shown without a destination")
	}
	disabled := newTestServer(t)
	if strings.Contains(signIn(disabled, disabled.(*Server), "app"), `action="/auth/approval/start"`) {
		t.Errorf("approval form is shown while disabled")
	}
}

func findCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestRequesterIP(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"cloudfront viewer address", map[string]string{"CloudFront-Viewer-Address": "203.0.113.5:443", "X-Forwarded-For": "10.0.0.1, 198.51.100.7"}, "203.0.113.5"},
		{"cloudfront ipv6", map[string]string{"CloudFront-Viewer-Address": "2001:db8::1:443"}, "2001:db8::1"},
		{"spoofed first xff entry is ignored", map[string]string{"X-Forwarded-For": "10.0.0.1, 198.51.100.7"}, "198.51.100.7"},
		{"remote addr", nil, "192.0.2.1:1234"},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", "https://auth.example.com/", nil)
		req.RemoteAddr = "192.0.2.1:1234"
		for k, v := range tt.headers {
			req.Header.Set(k, v)
		}
		if got := requesterIP(req); got != tt.want {
			t.Errorf("%s: requesterIP() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestIsSameOriginRequest(t *testing.T) {
	e := newApprovalEnv(t)
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		// 認証画面は Referrer-Policy: no-referrer なので、同じサイトのフォーム送信でも Origin が null になる
		{"same-origin with null origin", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "null"}, true},
		{"same-origin", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://auth.example.com"}, true},
		{"cross-site", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://auth.example.com"}, false},
		{"same-site (other subdomain)", map[string]string{"Sec-Fetch-Site": "same-site"}, false},
		{"old browser, same origin", map[string]string{"Origin": "https://auth.example.com"}, true},
		{"old browser, other origin", map[string]string{"Origin": "https://evil.example.net"}, false},
		{"old browser, null origin", map[string]string{"Origin": "null"}, false},
		{"no headers", nil, true},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("POST", "https://auth.example.com/auth/approval/start", nil)
		for k, v := range tt.headers {
			req.Header.Set(k, v)
		}
		if got := e.s.isSameOriginRequest(req); got != tt.want {
			t.Errorf("%s: isSameOriginRequest() = %v, want %v", tt.name, got, tt.want)
		}
	}
}
