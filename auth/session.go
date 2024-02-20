package auth

import (
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

type LoginSession struct {
	Email      string
	Sub        string
	ValidUntil time.Time
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

	if email == "" || sub == "" || validUntil.Before(time.Now()) {
		return &LoginSession{}
	}

	return &LoginSession{
		Email:      email,
		Sub:        sub,
		ValidUntil: validUntil,
	}
}
