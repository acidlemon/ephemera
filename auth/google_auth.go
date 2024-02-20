package auth

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type googleAuthProvider struct {
	p *oidc.Provider
}

func NewGoogleAuthProvider(ctx context.Context) (OIDCProvider, error) {
	cfg := oidc.ProviderConfig{
		IssuerURL:     "https://accounts.google.com",
		AuthURL:       "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:      "https://oauth2.googleapis.com/token",
		DeviceAuthURL: "https://oauth2.googleapis.com/device/code",
		UserInfoURL:   "https://openidconnect.googleapis.com/v1/userinfo",
		JWKSURL:       "https://www.googleapis.com/oauth2/v3/certs",
		Algorithms:    []string{"RS256"},
	}
	p := cfg.NewProvider(ctx)

	return &googleAuthProvider{
		p: p,
	}, nil
}

func (g *googleAuthProvider) Verifier(config *oidc.Config) *oidc.IDTokenVerifier {
	return g.p.Verifier(config)
}

func (g *googleAuthProvider) Endpoint() oauth2.Endpoint {
	return g.p.Endpoint()
}
