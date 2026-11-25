package auth

import (
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

// ログイン方法
const (
	AuthMethodGoogle   = "google"
	AuthMethodApproval = "approval" // 承認方式（ほかの人の承認で、その人のアドレスとして通った）
)

type LoginSession struct {
	Email      string
	Sub        string
	ValidUntil time.Time
	// AuthMethod はログイン方法（AuthMethodGoogle / AuthMethodApproval）
	AuthMethod string
	// AllowedSubdomain が空でなければ、このセッションはそのサブドメインでだけ有効（承認方式のセッション）
	AllowedSubdomain string
}

// ValidFor は、このセッションが subdomain で使えるかを返す。
func (l *LoginSession) ValidFor(subdomain string) bool {
	return l.Email != "" && (l.AllowedSubdomain == "" || l.AllowedSubdomain == subdomain)
}

func ExtractSession(req *http.Request, store *sessions.CookieStore) *LoginSession {
	commonSession, err := store.Get(req, commonSessionName)
	if err != nil {
		return &LoginSession{}
	}
	email, _ := commonSession.Values["email"].(string)
	sub, _ := commonSession.Values["sub"].(string)
	validUntilEpoch, _ := commonSession.Values["valid_until"].(int64)
	validUntil := time.Unix(validUntilEpoch, 0)
	method, _ := commonSession.Values["auth_method"].(string)
	allowedSubdomain, _ := commonSession.Values["allowed_subdomain"].(string)

	if email == "" || sub == "" || validUntil.Before(time.Now()) {
		return &LoginSession{}
	}
	if method == "" {
		// 承認方式を入れる前に発行されたセッションは Google でのログイン
		method = AuthMethodGoogle
	}
	if method != AuthMethodGoogle && allowedSubdomain == "" {
		// Google 以外のログインは必ずサブドメインに絞って発行する。絞られていなければ壊れているので使わない
		return &LoginSession{}
	}

	return &LoginSession{
		Email:            email,
		Sub:              sub,
		ValidUntil:       validUntil,
		AuthMethod:       method,
		AllowedSubdomain: allowedSubdomain,
	}
}
