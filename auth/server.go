package auth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const authSessionName = "ephemera_auth_session"
const commonSessionName = "ephemera_session"

type Server struct {
	mux           *http.ServeMux
	a             *Authenticator
	store         *sessions.CookieStore
	authSubdomain string
	hostSuffix    string

	// 承認方式のログイン。approvals が設定されているときだけ有効
	approvals   ApprovalStore
	authorities map[string][]string
}

type ServerOptions struct {
	CookieStore   *sessions.CookieStore
	ClientID      string
	ClientSecret  string
	HostSuffix    string
	AuthSubdomain string

	// 承認方式のログイン（任意）。ApprovalStore を設定すると有効になる。
	// Authorities は authorities.json の内容（メールアドレス → 許可するサブドメインの一覧）。承認できる人の判定に使う。
	ApprovalStore ApprovalStore
	Authorities   map[string][]string
}

var (
	defaultPage *template.Template
	signInPage  *template.Template
)

// prepare html templates
func init() {
	defaultTmpl :=
		`{{ define "main" }}
  <h2>Your Profile</h2>
  {{ if eq .Email "" }}
    Not Logged in.
    <p><a href="/auth/sign_in">Sign In</a></p>
  {{ else }}
    Email: {{ .Email }}
  {{ end }}
{{ end }}`

	signInTmpl := `{{ define "main" }}
	<h2>You need to login</h2>
	<form method="get" action="/auth/start">
	  <input type="hidden" name="p" value="{{ .Path }}" />
	  <input type="hidden" name="s" value="{{ .Subdomain }}" />
	  <p>
		<input type="submit" value="" class="google-signin" aria-label="Sign in with Google" />
	  </p>
	</form>
	{{ if .Approval }}
	<h3>Or ask a teammate to let you in</h3>
	<p>A teammate who can access this service approves your request, and you sign in as that teammate for this service only.</p>
	<form method="post" action="/auth/approval/start">
	  <input type="hidden" name="p" value="{{ .Path }}" />
	  <input type="hidden" name="s" value="{{ .Subdomain }}" />
	  <p><input type="submit" value="Request approval" /></p>
	</form>
	{{ end }}
	{{ end }}`

	layout := template.Must(template.New("layout").Parse(layoutHTML))
	defaultPage = template.Must(template.Must(layout.Clone()).Parse(defaultTmpl))
	signInPage = template.Must(template.Must(layout.Clone()).Parse(signInTmpl))
}

// サブドメインとして使えるラベル（英数字とハイフン、先頭末尾は英数字）
var subdomainPattern = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// sanitizeReturnTo はログイン後の戻り先を検証し、安全でない値を既定値に置き換える。
// サブドメインが不正なら ""（認証サブドメインに戻る）、パスが不正なら "/" を返す。
// https://{subdomain}.{hostSuffix}{path} を組み立てたときに別ホストへ飛ばないようにするため。
func sanitizeReturnTo(subdomain, path string) (string, string) {
	if !subdomainPattern.MatchString(subdomain) {
		subdomain = ""
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00\r\n\t") {
		path = "/"
	}
	return subdomain, path
}

func NewCookieStore(key string) *sessions.CookieStore {
	store := sessions.NewCookieStore([]byte(key))
	store.Options.HttpOnly = true
	store.Options.Secure = true
	store.Options.SameSite = http.SameSiteLaxMode
	store.MaxAge(0)
	return store
}

func NewServer(opts *ServerOptions) (http.Handler, error) {
	mux := http.NewServeMux()
	googleAuth, err := NewGoogleAuthProvider(context.Background())
	if err != nil {
		return nil, err
	}

	provider, err := NewGoogleAuthProvider(context.Background())
	conf := &oauth2.Config{
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		RedirectURL:  fmt.Sprintf("https://%s.%s/auth/callback", opts.AuthSubdomain, opts.HostSuffix),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}
	server := &Server{
		mux:           mux,
		a:             NewAuthenticator(conf, googleAuth),
		store:         opts.CookieStore,
		authSubdomain: opts.AuthSubdomain,
		hostSuffix:    opts.HostSuffix,
		approvals:     opts.ApprovalStore,
		authorities:   opts.Authorities,
	}

	mux.Handle("/auth/static/", staticHandler())
	mux.HandleFunc("/auth/start", server.StartAuth)
	mux.HandleFunc("/auth/callback", server.CallbackAuth)
	mux.HandleFunc("/auth/verify", server.VerifyAuth)
	mux.HandleFunc("/auth/sign_in", server.SignIn)
	mux.HandleFunc("/auth/approval", server.ApprovalPage)
	mux.HandleFunc("/auth/approval/start", server.StartApproval)
	mux.HandleFunc("/auth/approval/wait", server.WaitApproval)
	mux.HandleFunc("/auth/approval/decide", server.DecideApproval)
	mux.HandleFunc("/auth/unauthorized", server.Unauthorized)
	mux.HandleFunc("/", server.DefaultPage)

	return server, nil
}

func (s *Server) StartAuth(w http.ResponseWriter, req *http.Request) {
	// return path
	if err := req.ParseForm(); err != nil {
		WriteHttpError(w, NewHttpError(http.StatusBadRequest, "Body Parsing Error", err))
		return
	}
	subdomain, path := sanitizeReturnTo(req.Form.Get("s"), req.Form.Get("p"))

	state, nonce, url, expiresAt := s.a.StartAuthentication()
	session, _ := s.store.New(req, authSessionName)
	session.Values["state"] = state
	session.Values["nonce"] = nonce
	session.Values["return_path"] = path
	session.Values["return_subdomain"] = subdomain
	session.Values["expires_at"] = expiresAt.Unix()

	err := session.Save(req, w)
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Write Auth Session Error", err))
		return
	}
	http.Redirect(w, req, url, http.StatusFound)
}

func (s *Server) CallbackAuth(w http.ResponseWriter, req *http.Request) {
	session, err := s.store.Get(req, authSessionName)
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "No Session", err))
		return
	}

	expireAtUnix, ok := session.Values["expires_at"].(int64)
	if !ok {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "No Session", nil))
		return
	}
	if time.Now().After(time.Unix(expireAtUnix, 0)) {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "Authentication Session timeout", nil))
		return
	}

	// set CSRF token
	CSRFToken := base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(24))
	session.Values["csrf_token"] = CSRFToken
	if err := session.Save(req, w); err != nil {
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Write Auth Session Error", err))
		return
	}

	// write postback HTML
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	t := `<!doctype html>
<html>
<head>
  <title>Redirecting...</title>
</head>
<body>
<main>
  <form method="post" action="/auth/verify">
    <input type="hidden" name="csrf_token" value="` + CSRFToken + `" />
    <input type="hidden" name="state" value="" />
    <input type="hidden" name="id_token" value="" />
  </form>
  <script>` + callbackScript + `</script>
</main>
</body>
</html>
`
	io.WriteString(w, t)
}

func (s *Server) VerifyAuth(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		WriteHttpError(w, NewHttpError(http.StatusMethodNotAllowed, "Method Not Allowed", nil))
		return
	}

	// session validations
	session, err := s.store.Get(req, authSessionName)
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "No Session", err))
		return
	}
	state, _ := session.Values["state"].(string)
	if state == "" {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "No Session State", nil))
		return
	}
	csrfToken, _ := session.Values["csrf_token"].(string)
	if csrfToken == "" {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "No CSRF Token", nil))
		return
	}

	req.ParseForm()
	formCSRFToken := req.Form.Get("csrf_token")
	formState := req.Form.Get("state")
	if formCSRFToken != csrfToken {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "Detect Possibility of CSRF Attack", nil))
		return
	}
	if formState != state {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "Invalid State", nil))
		return
	}

	expireAtUnix, ok := session.Values["expires_at"].(int64)
	if !ok || time.Now().After(time.Unix(expireAtUnix, 0)) {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "Authentication Session timeout", nil))
		return
	}

	nonce, _ := session.Values["nonce"].(string)
	rawIDToken := req.Form.Get("id_token")
	token, err := s.a.VerifyAuthentication(req.Context(), rawIDToken, nonce)
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "Verification Error", err))
		return
	}

	returnSubdomain, _ := session.Values["return_subdomain"].(string)
	returnPath, _ := session.Values["return_path"].(string)
	subdomain, path := sanitizeReturnTo(returnSubdomain, returnPath)

	// delete authetication session
	session.Options.MaxAge = -1
	err = session.Save(req, w)
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Write Auth Session Error", err))
		return
	}

	s.completeLogin(w, req, loginGrant{
		Email:    token.Email,
		Sub:      token.Sub,
		Method:   AuthMethodGoogle,
		Validity: googleLoginValidity,
	}, subdomain, path)
}

// loginGrant はログインセッションに入れる内容。
type loginGrant struct {
	Email    string
	Sub      string // ログイン方法ごとに一意な識別子（Google なら sub クレーム、承認方式なら "approval:<コード>"）
	Method   string // AuthMethodGoogle / AuthMethodApproval
	Validity time.Duration
	// AllowedSubdomain が空でなければ、セッションをそのサブドメインだけに絞る
	AllowedSubdomain string
}

// Google でログインしたときのログインの有効期間
const googleLoginValidity = 7 * 24 * time.Hour

// completeLogin はログインを確定する。ログインセッション（ephemera_session）を作り、
// 戻り先 https://{subdomain}.{hostSuffix}{path} へリダイレクトする。
// subdomain と path は sanitizeReturnTo を通した値を渡すこと（subdomain が空なら認証サブドメインに戻る）。
func (s *Server) completeLogin(w http.ResponseWriter, req *http.Request, g loginGrant, subdomain, path string) {
	if subdomain == "" {
		subdomain = s.authSubdomain
	}

	commonSession, err := s.store.New(req, commonSessionName)
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Session Error", err))
		return
	}
	commonSession.Options.Domain = s.hostSuffix
	commonSession.Options.MaxAge = 60 * 60 * 24 * 30
	commonSession.Options.SameSite = http.SameSiteLaxMode
	commonSession.Values["email"] = g.Email
	commonSession.Values["sub"] = g.Sub
	commonSession.Values["valid_until"] = time.Now().Add(g.Validity).Unix()
	commonSession.Values["auth_method"] = g.Method
	commonSession.Values["allowed_subdomain"] = g.AllowedSubdomain
	if err := commonSession.Save(req, w); err != nil {
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Write Common Session Error", err))
		return
	}
	http.Redirect(w, req, fmt.Sprintf("https://%s.%s%s", subdomain, s.hostSuffix, path), http.StatusFound)
}

func (s *Server) SignIn(w http.ResponseWriter, req *http.Request) {
	gateSession, err := s.store.Get(req, "ephemera_gate")
	if err != nil {
		log.Println("failed to get gate session:", err.Error())
	}

	path, _ := gateSession.Values["path"].(string)
	subdomain, _ := gateSession.Values["subdomain"].(string)

	gateSession.Options.MaxAge = -1
	gateSession.Save(req, w)

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	approval := ""
	if s.approvalEnabled() && subdomain != "" {
		// 承認方式のセッションは行き先に絞るので、行き先があるときだけ出す
		approval = "1"
	}
	signInPage.Execute(w, map[string]string{
		"Title":     "Authorization Required - Ephemeral Gate",
		"Heading":   "Authorization Required",
		"Path":      path,
		"Subdomain": subdomain,
		"Approval":  approval,
	})
}

func (s *Server) Unauthorized(w http.ResponseWriter, req *http.Request) {
	WriteHttpError(w, NewHttpError(http.StatusForbidden, "No Access Permission", nil))
}

func (s *Server) DefaultPage(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.Redirect(w, req, "/", http.StatusFound)
		return
	}

	commonSession, err := s.store.Get(req, commonSessionName)
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Session Error", err))
		return
	}
	email, _ := commonSession.Values["email"].(string)
	// sub := commonSession.Values["sub"].(string)
	// validUntil := time.Unix(commonSession.Values["valid_until"].(int64), 0)

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	defaultPage.Execute(w, map[string]string{
		"Title":   "Ephemeral Gate",
		"Heading": "Ephemeral Gate",
		"Email":   email,
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header(), s.hostSuffix)
	// debug := NewDebugWriter(w, r)
	// s.mux.ServeHTTP(debug, r)
	s.mux.ServeHTTP(w, r)
}

type httpError struct {
	code    int
	message string
	detail  error
}

type HttpError interface {
	Error() string
	StatusCode() int
	Detail() error
}

func NewHttpError(code int, message string, detail error) HttpError {
	return &httpError{
		code:    code,
		message: message,
		detail:  detail,
	}
}

func (e *httpError) Error() string {
	return e.message
}
func (e *httpError) StatusCode() int {
	return e.code
}
func (e *httpError) Detail() error {
	return e.detail
}

var errorPage = template.Must(template.New("errorHTML").Parse(errorHTML))

// NewErrorID はエラーをログと突き合わせるための短い ID を返す。
func NewErrorID() string {
	return hex.EncodeToString(securecookie.GenerateRandomKey(6))
}

// WriteHttpError はエラーページを返す。
// 内部の詳細（HttpError の Detail や、HttpError 以外のエラーの文字列）は画面に出さずログにだけ出し、
// 画面には問い合わせ用のエラー ID を表示する。
func WriteHttpError(w http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	message := http.StatusText(statusCode)
	var detail error = err
	if httpErr, ok := err.(HttpError); ok {
		statusCode = httpErr.StatusCode()
		message = httpErr.Error()
		detail = httpErr.Detail()
	}

	errorID := NewErrorID()
	if detail != nil {
		log.Printf("error id=%s status=%d message=%q detail=%q", errorID, statusCode, message, detail.Error())
	} else {
		log.Printf("error id=%s status=%d message=%q", errorID, statusCode, message)
	}

	if statusCode == http.StatusUnauthorized {
		// hide failure reason
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if w.Header().Get("Content-Security-Policy") == "" {
		// 認証サーバーの外（アプリ側のサブドメイン）から呼ばれた場合。フォームはないので送信先は許可しない
		setSecurityHeaders(w.Header(), "")
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(statusCode)
	errorPage.Execute(w, map[string]string{
		"StatusCode":    fmt.Sprintf("%d", statusCode),
		"StatusMessage": http.StatusText(statusCode),
		"ErrorMessage":  message,
		"ErrorID":       errorID,
	})
}

const errorHTML = `<!doctype html>
<html>
<head>
  <title>{{ .StatusCode }} {{ .StatusMessage }}</title>
  <link rel="stylesheet" href="/auth/static/water.min.css">
  <link rel="stylesheet" href="/auth/static/ephemera.css">
</head>
<body>
<header>
  <h1>Authorization Required</h1>
</header>
<main>
  <h2>{{ .StatusCode }} {{ .StatusMessage }}</h2>
  <blockquote>
    <dl>
      <dt>Reason</dt><dd>{{ .ErrorMessage }}</dd>
    </dl>
    <dl>
      <dt>Error ID</dt><dd><code>{{ .ErrorID }}</code></dd>
    </dl>
  </blockquote>
  <p><a href="/">back</a></p>
</main>
</body>
</html>
`

const layoutHTML = `<!doctype html>
<html>
<head>
  <title>{{ .Title }}</title>
  <link rel="stylesheet" href="/auth/static/water.min.css">
  <link rel="stylesheet" href="/auth/static/ephemera.css">
</head>
<body>
<header>
  <h1>{{ .Heading }}</h1>
</header>
{{ template "main" . }}
</body>
</html>
`
