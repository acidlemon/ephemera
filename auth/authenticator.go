package auth

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type OIDCProvider interface {
	Verifier(config *oidc.Config) *oidc.IDTokenVerifier
	Endpoint() oauth2.Endpoint
}

type openIDToken struct {
	Issuer   string `json:"iss"`
	Sub      string `json:"sub"`
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
	Name     string `json:"name"`
}

type Authenticator struct {
	oidcConf *oauth2.Config
	provider OIDCProvider
}

func NewAuthenticator(conf *oauth2.Config, provider OIDCProvider) *Authenticator {
	return &Authenticator{
		oidcConf: conf,
		provider: provider,
	}
}

// OpenID Connectを利用した認証の開始
func (a *Authenticator) StartAuthentication() (string, string, time.Time) {
	state := base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(24))
	nonce := base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(24))

	// code flowをimplicit flowに変更
	u := a.oidcConf.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("response_type", "id_token"),
	)
	expiresAt := time.Now().Add(5 * time.Minute)

	return state, u, expiresAt
}

// OpenID Connectの認証結果の検証
func (a *Authenticator) VerifyAuthentication(ctx context.Context, rawIDToken string) (*openIDToken, error) {
	var verifier = a.provider.Verifier(&oidc.Config{ClientID: a.oidcConf.ClientID, InsecureSkipSignatureCheck: true})

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, errors.Wrap(err, "Verification failed")
	}

	// Extract custom claims
	var claims openIDToken
	if err := idToken.Claims(&claims); err != nil {
		// handle error
		return nil, err
	}

	// normalize issuer (remove "https://" for Google)
	claims.Issuer = strings.Replace(claims.Issuer, "https://", "", -1)

	return &claims, nil
}
