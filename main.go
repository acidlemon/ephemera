package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/acidlemon/ephemera/auth"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fujiwara/ridge"
	"github.com/gorilla/sessions"
)

type HostRecord struct {
	Subdomain    string    `json:"subdomain"`
	Target       string    `json:"target"`
	ExpireAt     time.Time `json:"expire_at"`
	NeedAuth     bool      `json:"need_auth"`
	ExcludePaths []string  `json:"exclude_paths"`
}

type AuthorityRecords map[string][]string

const region = "ap-northeast-1"

var (
	store          *sessions.CookieStore
	bucketName     string
	hostsKey       string
	authoritiesKey string
	hostSuffix     string
	authSubdomain  string
	clientID       string
	clientSecret   string
	notFoundPage   string
	originSecret   string
)

// CloudFront などの手前のプロキシがオリジンに付けるヘッダー。
// EPHEMERA_ORIGIN_SECRET を設定すると、この値が一致しないリクエストは受け付けない。
// "X-Ephemera-" で始まるのでバックエンドへの転送時には取り除かれる。
const headerOriginSecret = "X-Ephemera-Origin-Secret"

func MustEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("%s is not set", key)
	}
	return value
}

func initialize() {
	hostsKey = "hosts.json"
	authoritiesKey = "authorities.json"

	bucketName = MustEnv("EPHEMERA_S3_BUCKET_NAME")
	hostSuffix = MustEnv("EPHEMERA_HOST_SUFFIX")
	authSubdomain = MustEnv("EPHEMERA_AUTH_SUBDOMAIN")
	clientID = MustEnv("EPHEMERA_CLIENT_ID")
	clientSecret = MustEnv("EPHEMERA_CLIENT_SECRET")

	// 任意。設定すると手前のプロキシを経由しない直接アクセスを拒否する
	originSecret = os.Getenv("EPHEMERA_ORIGIN_SECRET")

	storekey := MustEnv("EPHEMERA_SESSION_KEY")
	store = auth.NewCookieStore(storekey)

	notFoundPage = `<!DOCTYPE html>
<html>
<head>
	<title>404 Not Found</title>
</head>
<body>
	<h1>Not Found</h1>
	<p>The requested URL was not found on this server.</p>
</body>
</html>
`
}

func fetchConfigRecords() ([]*HostRecord, AuthorityRecords, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	s3client := s3.NewFromConfig(cfg)
	hosts := []*HostRecord{}
	authorities := AuthorityRecords{}
	{
		result, err := s3client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(hostsKey),
		})
		if err != nil {
			log.Printf("Couldn't get object %v:%v. Here's why: %v\n", bucketName, hostsKey, err)
			return nil, nil, err
		}
		defer result.Body.Close()

		err = json.NewDecoder(result.Body).Decode(&hosts)
		if err != nil {
			log.Printf("Couldn't decode json. Here's why: %v\n", err)
			return nil, nil, err
		}
	}

	{
		result, err := s3client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(authoritiesKey),
		})
		if err != nil {
			log.Printf("Couldn't get object %v:%v. Here's why: %v\n", bucketName, authoritiesKey, err)
			return nil, nil, err
		}
		defer result.Body.Close()

		err = json.NewDecoder(result.Body).Decode(&authorities)
		if err != nil {
			log.Printf("Couldn't decode json. Here's why: %v\n", err)
			return nil, nil, err
		}
	}

	return hosts, authorities, nil
}

func IsExcludedPath(excludePaths []string, path string) bool {
	for _, p := range excludePaths {
		if matchWildcard(p, path) {
			return true
		}
	}
	return false
}

// extractSubdomain は host が {label}.{suffix} の形ならその label を返す。
// ポート番号と末尾の "." は無視し、大小文字は区別しない。label が複数段（a.b.{suffix}）なら不一致とする。
func extractSubdomain(host, suffix string) (string, bool) {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	suffix = "." + strings.Trim(strings.ToLower(suffix), ".")
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	label := strings.TrimSuffix(host, suffix)
	if label == "" || strings.Contains(label, ".") {
		return "", false
	}
	return label, true
}

// wildcardCache caches compiled regexes keyed by pattern. A nil value means
// the pattern contains no wildcard and should be compared exactly.
var wildcardCache sync.Map

// matchWildcard reports whether path matches the pattern.
// "*" matches any sequence of characters except "/" (a single path segment),
// while "**" matches any sequence of characters including "/" (multiple levels).
// e.g. "/" matches only "/", "/powawa/*/create" matches "/powawa/foo/create"
// but not "/powawa/a/b/create", and "/powawa/**/create" matches both.
func matchWildcard(pattern, path string) bool {
	re := compileWildcard(pattern)
	if re == nil {
		// no wildcard: exact match
		return pattern == path
	}
	return re.MatchString(path)
}

func compileWildcard(pattern string) *regexp.Regexp {
	if v, ok := wildcardCache.Load(pattern); ok {
		re, _ := v.(*regexp.Regexp)
		return re
	}

	var re *regexp.Regexp
	if strings.Contains(pattern, "*") {
		var b strings.Builder
		b.WriteString("^")
		for i := 0; i < len(pattern); i++ {
			if pattern[i] == '*' {
				if i+1 < len(pattern) && pattern[i+1] == '*' {
					b.WriteString(".*")
					i++
				} else {
					b.WriteString("[^/]*")
				}
				continue
			}
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
		b.WriteString("$")
		re, _ = regexp.Compile(b.String())
	}

	wildcardCache.Store(pattern, re)
	return re
}

// ephemera が発行するクッキーの接頭辞。バックエンドには渡さない。
const ephemeraCookiePrefix = "ephemera_"

// バックエンドにログイン中のユーザーを伝えるヘッダー
const (
	headerEphemeraEmail = "X-Ephemera-Email"
	headerEphemeraSub   = "X-Ephemera-Sub"
)

// prepareUpstreamRequest はバックエンドに転送する前のリクエストを整える。
//   - ephemera_* クッキーを取り除く（バックエンドにログインクッキーを渡さない）
//   - クライアントが送ってきた X-Ephemera-* ヘッダーを捨てる（X_Ephemera_* などの表記揺れも含む。なりすまし防止）
//   - ログイン中なら X-Ephemera-Email / X-Ephemera-Sub を付ける
func prepareUpstreamRequest(req *http.Request, login *auth.LoginSession) {
	stripEphemeraCookies(req.Header)

	// "_" を "-" と同一視するバックエンド（Rack/WSGI/CGI など）もあるため、
	// 大小文字と "_" / "-" の違いを無視して比較する
	for name := range req.Header {
		n := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
		if strings.HasPrefix(n, "x-ephemera-") {
			delete(req.Header, name)
		}
	}

	if login != nil && login.Email != "" {
		req.Header.Set(headerEphemeraEmail, login.Email)
		req.Header.Set(headerEphemeraSub, login.Sub)
	}
}

func stripEphemeraCookies(h http.Header) {
	r := &http.Request{Header: http.Header{"Cookie": h.Values("Cookie")}}
	var kept []string
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, ephemeraCookiePrefix) {
			continue
		}
		kept = append(kept, c.Name+"="+c.Value)
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}

func emailOrAnonymous(login *auth.LoginSession) string {
	if login == nil || login.Email == "" {
		return "-"
	}
	return login.Email
}

func GeneralHandler(w http.ResponseWriter, req *http.Request) {
	if originSecret != "" &&
		subtle.ConstantTimeCompare([]byte(req.Header.Get(headerOriginSecret)), []byte(originSecret)) != 1 {
		log.Printf("rejected request without valid origin secret host=%q", req.Host)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	hosts, authorities, err := fetchConfigRecords()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"failed to fetch config:` + err.Error() + `"}`))
		return
	}
	now := time.Now()

	reqHost := req.Header.Get("X-Forwarded-Host")
	if reqHost == "" {
		reqHost = req.Host
	}
	subdomain, ok := extractSubdomain(reqHost, hostSuffix)
	if !ok {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(notFoundPage))
		return
	}

	// check auth subdomain
	if subdomain == authSubdomain {
		authServer, err := auth.NewServer(&auth.ServerOptions{
			CookieStore:   store,
			ClientID:      clientID,
			ClientSecret:  clientSecret,
			HostSuffix:    hostSuffix,
			AuthSubdomain: authSubdomain,
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"message":"failed to create auth server:` + err.Error() + `"}`))
			return
		}
		log.Println("authServer.ServeHTTP")
		authServer.ServeHTTP(w, req)
		return
	}

	for _, host := range hosts {
		if host.Subdomain == subdomain && host.ExpireAt.After(now) {
			// need auth?
			loginSession := auth.ExtractSession(req, store)
			if !IsExcludedPath(host.ExcludePaths, req.URL.Path) {
				if loginSession.Email == "" {
					// not logged in
					session, err := store.New(req, "ephemera_gate")
					if err != nil {
						log.Println("failed to create gate session:", err.Error())
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					session.Options.Domain = hostSuffix
					session.Options.SameSite = http.SameSiteLaxMode
					session.Values["subdomain"] = subdomain
					session.Values["path"] = req.URL.Path
					session.Save(req, w)
					http.Redirect(w, req, fmt.Sprintf("https://%s.%s/auth/sign_in", authSubdomain, hostSuffix), http.StatusFound)
					return
				}
				if host.NeedAuth {
					if subdomains, ok := authorities[loginSession.Email]; ok {
						if !slices.Contains(subdomains, subdomain) && !slices.Contains(subdomains, "*") {
							// unauthorized
							log.Printf("denied subdomain=%s method=%s path=%q email=%s reason=not_allowed", subdomain, req.Method, req.URL.Path, loginSession.Email)
							http.Error(w, "Unauthorized", http.StatusUnauthorized)
							return
						}
					} else {
						// unauthorized
						log.Printf("denied subdomain=%s method=%s path=%q email=%s reason=no_authority", subdomain, req.Method, req.URL.Path, loginSession.Email)
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
				}
			}

			prepareUpstreamRequest(req, loginSession)
			log.Printf("access subdomain=%s method=%s path=%q email=%s remote=%q",
				subdomain, req.Method, req.URL.Path, emailOrAnonymous(loginSession), req.Header.Get("X-Forwarded-For"))

			destUrl, _ := url.Parse("http://" + host.Target)
			rp := httputil.NewSingleHostReverseProxy(destUrl)
			rp.ServeHTTP(w, req)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(notFoundPage))
}

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags | log.Lmicroseconds)

	initialize()

	mux := http.NewServeMux()
	mux.HandleFunc("/", GeneralHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5003"
	}

	r := ridge.New(":"+port, "/", mux)
	r.StreamingResponse = true
	r.Run()
}
