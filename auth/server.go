package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
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
}

type ServerOptions struct {
	CookieStore   *sessions.CookieStore
	ClientID      string
	ClientSecret  string
	HostSuffix    string
	AuthSubdomain string
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
		<input type="submit" value="" style="background:url(data:image/png;base64,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); width:191px; height:46px; cursor: pointer; border:0px none;" />
	  </p>
	</form>
	{{ end }}`

	layout := template.Must(template.New("layout").Parse(layoutHTML))
	defaultPage = template.Must(template.Must(layout.Clone()).Parse(defaultTmpl))
	signInPage = template.Must(template.Must(layout.Clone()).Parse(signInTmpl))
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
	}

	mux.HandleFunc("/auth/start", server.StartAuth)
	mux.HandleFunc("/auth/callback", server.CallbackAuth)
	mux.HandleFunc("/auth/verify", server.VerifyAuth)
	mux.HandleFunc("/auth/sign_in", server.SignIn)
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
	path := req.Form.Get("p")
	if path == "" {
		path = "/"
	}
	subdomain := req.Form.Get("s")

	state, url, expiresAt := s.a.StartAuthentication()
	session, _ := s.store.New(req, authSessionName)
	session.Values["state"] = state
	session.Values["return_path"] = path
	session.Values["return_subdomain"] = subdomain
	session.Values["expires_at"] = expiresAt.Unix()

	err := session.Save(req, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	expireAtUnix := session.Values["expires_at"].(int64)
	expireAt := time.Unix(expireAtUnix, 0)
	if time.Now().Sub(expireAt) > 0 {
		WriteHttpError(w, fmt.Errorf("Authentication Session timeout"))
		return
	}

	// set CSRF token
	CSRFToken := base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(24))
	session.Values["csrf_token"] = CSRFToken
	session.Save(req, w)

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
  <script type="text/javascript">
    window.onload = function(){
      const params = new URLSearchParams(window.location.hash.substring(1))
      document.forms[0].elements["state"].value = params.get("state")
      document.forms[0].elements["id_token"].value = params.get("id_token")
      document.forms[0].submit()
    }
  </script>
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
	state := session.Values["state"].(string)
	if state == "" {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "No Session State", err))
		return
	}
	csrfToken := session.Values["csrf_token"].(string)
	if csrfToken == "" {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "No CSRF Token", err))
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

	expireAtUnix := session.Values["expires_at"].(int64)
	expireAt := time.Unix(expireAtUnix, 0)
	if time.Now().Sub(expireAt) > 0 {
		WriteHttpError(w, fmt.Errorf("Authentication Session timeout"))
		return
	}

	rawIDToken := req.Form.Get("id_token")
	token, err := s.a.VerifyAuthentication(req.Context(), rawIDToken)
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "Verification Error", err))
		return
	}

	subdomain := session.Values["return_subdomain"].(string)
	if subdomain == "" {
		subdomain = s.authSubdomain
	}
	path := session.Values["return_path"].(string)
	if path == "" {
		path = "/"
	}

	// delete authetication session
	session.Options.MaxAge = -1
	err = session.Save(req, w)
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Write Auth Session Error", err))
		return
	}

	// set authorization session
	commonSession, err := s.store.New(req, commonSessionName)
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Session Error", err))
		return
	}
	commonSession.Options.Domain = s.hostSuffix
	commonSession.Options.MaxAge = 60 * 60 * 24 * 30
	commonSession.Options.SameSite = http.SameSiteNoneMode
	commonSession.Values["email"] = token.Email
	commonSession.Values["sub"] = token.Sub
	commonSession.Values["valid_until"] = time.Now().Add(7 * 24 * time.Hour).Unix()
	err = commonSession.Save(req, w)
	if err != nil {
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

	signInPage.Execute(w, map[string]string{
		"Title":     "Authorization Required - Ephemeral Gate",
		"Heading":   "Authorization Required",
		"Path":      path,
		"Subdomain": subdomain,
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

func WriteHttpError(w http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	httpErr, ok := err.(HttpError)
	message := err.Error()
	detail := ""
	if ok {
		statusCode = httpErr.StatusCode()
		if httpErr.Detail() != nil {
			detail = httpErr.Detail().Error()
		}
	}

	tmpl := template.Must(template.New("errorHTML").Parse(errorHTML))

	switch statusCode {
	case http.StatusUnauthorized:
		// hide failure reason
		w.WriteHeader(http.StatusUnauthorized)
		break
	default:
		w.WriteHeader(statusCode)
		tmpl.Execute(w, map[string]string{
			"StatusCode":    fmt.Sprintf("%d", statusCode),
			"StatusMessage": http.StatusText(statusCode),
			"ErrorMessage":  message,
			"ErrorDetail":   detail,
		})
	}
	return
}

const errorHTML = `<!doctype html>
<html>
<head>
  <title>{{ .StatusCode }} {{ .StatusMessage }}</title>
  <!--link rel="stylesheet" href="https://newcss.net/new.min.css"-->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
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
    {{ if .ErrorDetail }}
    <dl>
      <dt>Detail</dt><dd>{{ .ErrorDetail }}</dd>
    </dl>
    {{ end }}
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
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<body>
<header>
  <h1>{{ .Heading }}</h1>
</header>
{{ template "main" . }}
</body>
</html>
`
