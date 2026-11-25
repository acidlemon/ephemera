package auth

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"io/fs"
	"net/http"
	"strings"
)

// 認証画面の CSS。外部 CDN に依存しないようバイナリに埋め込んで /auth/static/ から配信する。
// water.min.css は water.css v2.1.1（MIT License）。
//
//go:embed static/*.css
var staticFiles embed.FS

func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFiles, "static")
	fileServer := http.StripPrefix("/auth/static/", http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 認証画面の応答は no-store にしているが、静的ファイルはキャッシュしてよい
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fileServer.ServeHTTP(w, r)
	})
}

// /auth/callback で URL フラグメントの id_token を /auth/verify に POST するスクリプト。
// CSP で許可するためハッシュを計算するので、ページにはこの文字列をそのまま埋め込むこと。
const callbackScript = `
    window.onload = function(){
      const params = new URLSearchParams(window.location.hash.substring(1))
      document.forms[0].elements["state"].value = params.get("state")
      document.forms[0].elements["id_token"].value = params.get("id_token")
      document.forms[0].submit()
    }
  `

var callbackScriptHash = func() string {
	sum := sha256.Sum256([]byte(callbackScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// setSecurityHeaders は ephemera 自身が返すページ（認証画面・エラーページ）にセキュリティ用のヘッダーを付ける。
// バックエンドからの応答には付けない。
// hostSuffix が空でなければ、ログイン後のリダイレクト先（https://*.{hostSuffix}）へのフォーム送信を許可する。
func setSecurityHeaders(h http.Header, hostSuffix string) {
	formAction := "'none'"
	if hostSuffix != "" {
		// /auth/start は Google へ、/auth/verify はアプリのサブドメインへリダイレクトする。
		// Chrome はフォーム送信後のリダイレクト先にも form-action を適用する。
		formAction = "'self' https://accounts.google.com https://*." + strings.Trim(hostSuffix, ".")
	}
	csp := []string{
		"default-src 'none'",
		"style-src 'self'",
		"img-src data:",
		"script-src " + callbackScriptHash,
		"form-action " + formAction,
		"frame-ancestors 'none'",
		"base-uri 'none'",
	}
	h.Set("Content-Security-Policy", strings.Join(csp, "; "))
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
}
