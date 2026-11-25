package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/pkg/errors"
)

// 承認方式のログイン
//
//  1. 申請者がサインイン画面で「承認をリクエスト」を押す（POST /auth/approval/start）。
//     コードと待ち画面が出る（GET /auth/approval/wait。数秒ごとに自動で更新）
//  2. 申請者がコードを承認者に伝える（Slack の DM など）
//  3. 承認者が自分のブラウザ（Google でログイン済み）で /auth/approval を開き、コードを入力して承認する
//  4. 申請者の待ち画面が次に更新されたとき、承認者のアドレスで、行き先のサブドメインだけに絞ったセッションが発行される
const (
	approvalTTL            = 10 * time.Minute // 要求の有効期間
	approvalLoginValidity  = 24 * time.Hour   // 承認方式で入ったときのログインの有効期間（D-011）
	approvalRefreshSeconds = 3                // 待ち画面の更新間隔

	// 申請者のブラウザに入れる「コード.秘密の値」。秘密の値を持つブラウザだけがセッションを受け取れる
	approvalCookieName = "ephemera_approval"
	approvalCookiePath = "/auth/approval/"
)

var approvalTimeZone = time.FixedZone("JST", 9*60*60)

var (
	approvalWaitPage    *template.Template
	approvalStatusPage  *template.Template
	approvalApprovePage *template.Template
)

func init() {
	layout := template.Must(template.New("layout").Parse(layoutHTML))
	approvalWaitPage = template.Must(template.Must(layout.Clone()).Parse(`{{ define "main" }}
  <h2>Waiting for approval</h2>
  <p>Send this code to a teammate who can access <strong>{{ .Destination }}</strong>
     through a channel you normally use (for example, a direct message), and ask them to approve it at
     <code>{{ .ApprovalURL }}</code>.</p>
  <p class="approval-code"><strong><code>{{ .Code }}</code></strong></p>
  <p>This page checks for approval every few seconds. The request expires at {{ .ExpiresAt }}.</p>
{{ end }}`))
	approvalStatusPage = template.Must(template.Must(layout.Clone()).Parse(`{{ define "main" }}
  <h2>{{ .Status }}</h2>
  <p>{{ .Message }}</p>
  {{ if .Link }}<p><a href="{{ .Link }}">{{ .LinkText }}</a></p>{{ end }}
{{ end }}`))
	approvalApprovePage = template.Must(template.Must(layout.Clone()).Parse(`{{ define "main" }}
  <p>Signed in as <strong>{{ .Approver }}</strong></p>
  {{ if .Request }}
  <h2>Approve sign-in request {{ .Request.Code }}?</h2>
  <p>If you approve, the browser that made this request can access
     <strong>{{ .Destination }}</strong> <em>as you ({{ .Approver }})</em> for {{ .ValidHours }} hours.
     Only approve a code that the person sent you directly.</p>
  <table>
    <tr><th>Destination</th><td>{{ .Destination }}</td></tr>
    <tr><th>Requested at</th><td>{{ .CreatedAt }}</td></tr>
    <tr><th>Expires at</th><td>{{ .ExpiresAt }}</td></tr>
    <tr><th>IP address *</th><td>{{ .Request.RequesterIP }}</td></tr>
    <tr><th>Browser *</th><td>{{ .Request.RequesterUA }}</td></tr>
  </table>
  <p><small>* For reference only. These values can be faked by the requester.
     Decide based on whether the person sent you this code directly.</small></p>
  <form method="post" action="/auth/approval/decide">
    <input type="hidden" name="code" value="{{ .Request.Code }}" />
    <p>
      <button type="submit" name="action" value="approve">Approve</button>
      <button type="submit" name="action" value="deny">Deny</button>
    </p>
  </form>
  {{ else }}
  <h2>Approve a sign-in request</h2>
  {{ if .Error }}<p><strong>{{ .Error }}</strong></p>{{ end }}
  <form method="get" action="/auth/approval">
    <p>
      <label for="code">Code</label>
      <input type="text" id="code" name="code" required autocomplete="off" placeholder="XXXX-XXXX" />
    </p>
    <p><input type="submit" value="Look up" /></p>
  </form>
  {{ end }}
{{ end }}`))
}

func (s *Server) approvalEnabled() bool {
	return s.approvals != nil
}

// isSameOriginRequest は、自分（認証サブドメイン）のページから送られたリクエストかを判定する。
//
// Sec-Fetch-Site があればそれだけで判定する（いまのブラウザは必ず付ける）。
// 認証画面は Referrer-Policy: no-referrer なので、同じサイトの中のフォーム送信でも Origin が "null" になる。
// そのため Origin は、Sec-Fetch-Site を付けない古いブラウザのときだけ見る（"null" は弾く）。
// どちらのヘッダーもなければ許可する。
func (s *Server) isSameOriginRequest(req *http.Request) bool {
	if site := req.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	if origin := req.Header.Get("Origin"); origin != "" {
		return origin == fmt.Sprintf("https://%s.%s", s.authSubdomain, s.hostSuffix)
	}
	return true
}

func setApprovalCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     approvalCookieName,
		Value:    value,
		Path:     approvalCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func hashApprovalSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// requesterIP は承認者に参考として見せる申請者の IP アドレスを返す。
// X-Forwarded-For の先頭はクライアントが自由に書けるので使わない。
// CloudFront が付ける CloudFront-Viewer-Address（"IP:ポート"）があればそれを、
// なければ X-Forwarded-For の末尾（手前のプロキシが付け足した値）を使う。
// どちらも直接アクセスされれば偽れるので、確かな値ではない（画面にもそう書く）。
func requesterIP(req *http.Request) string {
	if v := req.Header.Get("CloudFront-Viewer-Address"); v != "" {
		if i := strings.LastIndex(v, ":"); i > 0 {
			return strings.Trim(v[:i], "[]")
		}
		return v
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return req.RemoteAddr
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Server) destination(subdomain, path string) string {
	return fmt.Sprintf("https://%s.%s%s", subdomain, s.hostSuffix, path)
}

func (s *Server) writeApprovalStatus(w http.ResponseWriter, code int, status, message string) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(code)
	approvalStatusPage.Execute(w, map[string]string{
		"Title":   status + " - Ephemeral Gate",
		"Heading": "Ephemeral Gate",
		"Status":  status,
		"Message": message,
	})
}

// StartApproval は POST /auth/approval/start。承認の要求を作り、待ち画面へ送る。
// 申請者は何も入力しない（誰として通すかは承認者が決まる）ので、登録の有無を調べる手がかりにならない。
func (s *Server) StartApproval(w http.ResponseWriter, req *http.Request) {
	if !s.approvalEnabled() {
		http.NotFound(w, req)
		return
	}
	if req.Method != http.MethodPost {
		WriteHttpError(w, NewHttpError(http.StatusMethodNotAllowed, "Method Not Allowed", nil))
		return
	}
	if !s.isSameOriginRequest(req) {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "Cross-site request is not allowed", nil))
		return
	}
	if err := req.ParseForm(); err != nil {
		WriteHttpError(w, NewHttpError(http.StatusBadRequest, "Body Parsing Error", err))
		return
	}
	subdomain, path := sanitizeReturnTo(req.PostForm.Get("s"), req.PostForm.Get("p"))
	if subdomain == "" {
		// 承認方式のセッションは行き先のサブドメインに絞るので、行き先がないと受け付けられない（D-012）
		WriteHttpError(w, NewHttpError(http.StatusBadRequest, "Open the service you want to use first, then request approval from its sign-in page", nil))
		return
	}

	secret := base64.RawURLEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
	now := time.Now()
	r := &ApprovalRequest{
		SecretHash:  hashApprovalSecret(secret),
		Subdomain:   subdomain,
		Path:        path,
		CreatedAt:   now,
		ExpiresAt:   now.Add(approvalTTL),
		RequesterIP: truncate(requesterIP(req), 100),
		RequesterUA: truncate(req.UserAgent(), 300),
		Status:      ApprovalPending,
	}
	var err error
	for i := 0; i < 3; i++ {
		if r.Code, err = newApprovalCode(); err != nil {
			break
		}
		if err = s.approvals.Create(req.Context(), r); !errors.Is(err, ErrApprovalConflict) {
			break
		}
	}
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Failed to create approval request", err))
		return
	}

	log.Printf("approval requested code=%s subdomain=%s ip=%q", r.Code, r.Subdomain, r.RequesterIP)
	setApprovalCookie(w, r.Code+"."+secret, int(approvalTTL.Seconds()))
	http.Redirect(w, req, "/auth/approval/wait", http.StatusSeeOther)
}

// WaitApproval は GET /auth/approval/wait。申請者の待ち画面。
// 承認されていれば、要求を使用済みにしてからセッションを発行する。
func (s *Server) WaitApproval(w http.ResponseWriter, req *http.Request) {
	if !s.approvalEnabled() {
		http.NotFound(w, req)
		return
	}
	c, err := req.Cookie(approvalCookieName)
	code, secret, ok := "", "", false
	if err == nil {
		code, secret, ok = strings.Cut(c.Value, ".")
	}
	if !ok || code == "" || secret == "" {
		s.writeApprovalStatus(w, http.StatusForbidden, "No request", "There is no approval request in this browser.")
		return
	}

	r, etag, err := s.approvals.Get(req.Context(), code)
	if errors.Is(err, ErrApprovalNotFound) {
		setApprovalCookie(w, "", -1)
		s.writeApprovalStatus(w, http.StatusForbidden, "Request expired", "The request was not found or has expired. Please start again.")
		return
	}
	if err != nil {
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Failed to load approval request", err))
		return
	}
	if subtle.ConstantTimeCompare([]byte(hashApprovalSecret(secret)), []byte(r.SecretHash)) != 1 {
		setApprovalCookie(w, "", -1)
		s.writeApprovalStatus(w, http.StatusForbidden, "No request", "There is no approval request in this browser.")
		return
	}
	if time.Now().After(r.ExpiresAt) && r.Status != ApprovalDenied && r.Status != ApprovalConsumed {
		setApprovalCookie(w, "", -1)
		s.writeApprovalStatus(w, http.StatusForbidden, "Request expired", "The request has expired. Please start again.")
		return
	}

	switch r.Status {
	case ApprovalPending:
		w.Header().Set("Refresh", fmt.Sprintf("%d", approvalRefreshSeconds))
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		approvalWaitPage.Execute(w, map[string]string{
			"Title":       "Waiting for approval - Ephemeral Gate",
			"Heading":     "Ephemeral Gate",
			"Code":        r.Code,
			"Destination": s.destination(r.Subdomain, "/"),
			"ApprovalURL": fmt.Sprintf("https://%s.%s/auth/approval", s.authSubdomain, s.hostSuffix),
			"ExpiresAt":   r.ExpiresAt.In(approvalTimeZone).Format("15:04:05 MST"),
		})
	case ApprovalDenied:
		setApprovalCookie(w, "", -1)
		s.writeApprovalStatus(w, http.StatusForbidden, "Request denied", "The request was denied.")
	case ApprovalApproved:
		approver := r.ApproverEmail
		// 承認してから authorities.json が変わっているかもしれないので、承認者の権限を確かめ直す
		if !s.canApprove(approver, r.Subdomain) {
			setApprovalCookie(w, "", -1)
			s.writeApprovalStatus(w, http.StatusForbidden, "Request denied", "The approver can no longer access this service.")
			return
		}
		// 使用済みにできたときだけセッションを発行する（同時に来ても1回だけ）
		r.Status = ApprovalConsumed
		if err := s.approvals.Update(req.Context(), r, etag); err != nil {
			if errors.Is(err, ErrApprovalConflict) {
				s.writeApprovalStatus(w, http.StatusConflict, "Already used", "This request has already been used.")
				return
			}
			WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Failed to update approval request", err))
			return
		}
		setApprovalCookie(w, "", -1)
		log.Printf("approval login code=%s approver=%q subdomain=%s ip=%q", r.Code, approver, r.Subdomain, requesterIP(req))
		subdomain, path := sanitizeReturnTo(r.Subdomain, r.Path)
		s.completeLogin(w, req, loginGrant{
			Email:            approver,
			Sub:              "approval:" + r.Code,
			Method:           AuthMethodApproval,
			Validity:         approvalLoginValidity,
			AllowedSubdomain: subdomain,
		}, subdomain, path)
	default:
		setApprovalCookie(w, "", -1)
		s.writeApprovalStatus(w, http.StatusForbidden, "Already used", "This request has already been used.")
	}
}

// approverOf は承認者になれるログインを返す。Google でログインしていなければ nil。
// 承認方式で入ったセッションでは承認できない（承認の連鎖を防ぐ）。
func (s *Server) approverOf(req *http.Request) *LoginSession {
	l := ExtractSession(req, s.store)
	if l.Email == "" || l.AuthMethod != AuthMethodGoogle {
		return nil
	}
	return l
}

// canApprove は、承認者が行き先のサブドメイン（または *）を許可されているかを返す（D-009）。
func (s *Server) canApprove(approverEmail, subdomain string) bool {
	subdomains, ok := s.authorities[approverEmail]
	return ok && (slices.Contains(subdomains, subdomain) || slices.Contains(subdomains, "*"))
}

// loadDecidable は、承認者が今決められる要求を返す。決められなければ nil と理由を返す。
func (s *Server) loadDecidable(req *http.Request, approver *LoginSession, rawCode string) (*ApprovalRequest, string, string) {
	const notFound = "No pending request with this code that you can approve."
	code := normalizeApprovalCode(rawCode)
	if code == "" {
		return nil, "", "The code should look like XXXX-XXXX."
	}
	r, etag, err := s.approvals.Get(req.Context(), code)
	if err != nil {
		if !errors.Is(err, ErrApprovalNotFound) {
			log.Printf("approval lookup failed code=%s err=%v", code, err)
		}
		return nil, "", notFound
	}
	if r.Status != ApprovalPending || time.Now().After(r.ExpiresAt) || !s.canApprove(approver.Email, r.Subdomain) {
		return nil, "", notFound
	}
	return r, etag, ""
}

func (s *Server) writeApprovePage(w http.ResponseWriter, code int, approver *LoginSession, r *ApprovalRequest, errMsg string) {
	data := map[string]any{
		"Title":      "Approve sign-in - Ephemeral Gate",
		"Heading":    "Ephemeral Gate",
		"Approver":   approver.Email,
		"Error":      errMsg,
		"ValidHours": int(approvalLoginValidity.Hours()),
	}
	if r != nil {
		data["Request"] = r
		data["Destination"] = s.destination(r.Subdomain, r.Path)
		data["CreatedAt"] = r.CreatedAt.In(approvalTimeZone).Format("2006-01-02 15:04:05 MST")
		data["ExpiresAt"] = r.ExpiresAt.In(approvalTimeZone).Format("2006-01-02 15:04:05 MST")
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(code)
	approvalApprovePage.Execute(w, data)
}

// ApprovalPage は GET /auth/approval。承認者がコードを入力し、要求の中身を確かめる画面。
func (s *Server) ApprovalPage(w http.ResponseWriter, req *http.Request) {
	if !s.approvalEnabled() {
		http.NotFound(w, req)
		return
	}
	approver := s.approverOf(req)
	if approver == nil {
		if l := ExtractSession(req, s.store); l.Email != "" {
			WriteHttpError(w, NewHttpError(http.StatusForbidden, "Sign in with Google to approve requests", nil))
			return
		}
		http.Redirect(w, req, "/auth/start?p=/auth/approval", http.StatusFound)
		return
	}
	rawCode := req.URL.Query().Get("code")
	if rawCode == "" {
		s.writeApprovePage(w, http.StatusOK, approver, nil, "")
		return
	}
	r, _, errMsg := s.loadDecidable(req, approver, rawCode)
	if r == nil {
		s.writeApprovePage(w, http.StatusNotFound, approver, nil, errMsg)
		return
	}
	s.writeApprovePage(w, http.StatusOK, approver, r, "")
}

// DecideApproval は POST /auth/approval/decide。承認・拒否を記録する。
func (s *Server) DecideApproval(w http.ResponseWriter, req *http.Request) {
	if !s.approvalEnabled() {
		http.NotFound(w, req)
		return
	}
	if req.Method != http.MethodPost {
		WriteHttpError(w, NewHttpError(http.StatusMethodNotAllowed, "Method Not Allowed", nil))
		return
	}
	if !s.isSameOriginRequest(req) {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "Cross-site request is not allowed", nil))
		return
	}
	approver := s.approverOf(req)
	if approver == nil {
		WriteHttpError(w, NewHttpError(http.StatusForbidden, "Sign in with Google to approve requests", nil))
		return
	}
	if err := req.ParseForm(); err != nil {
		WriteHttpError(w, NewHttpError(http.StatusBadRequest, "Body Parsing Error", err))
		return
	}
	action := req.PostForm.Get("action")
	if action != "approve" && action != "deny" {
		WriteHttpError(w, NewHttpError(http.StatusBadRequest, "Unknown action", nil))
		return
	}
	r, etag, errMsg := s.loadDecidable(req, approver, req.PostForm.Get("code"))
	if r == nil {
		s.writeApprovePage(w, http.StatusNotFound, approver, nil, errMsg)
		return
	}

	r.Status = ApprovalDenied
	if action == "approve" {
		r.Status = ApprovalApproved
	}
	r.ApproverEmail = approver.Email
	r.DecidedAt = time.Now()
	if err := s.approvals.Update(req.Context(), r, etag); err != nil {
		if errors.Is(err, ErrApprovalConflict) {
			s.writeApprovePage(w, http.StatusConflict, approver, nil, "This request was changed by someone else. Please look it up again.")
			return
		}
		WriteHttpError(w, NewHttpError(http.StatusInternalServerError, "Failed to update approval request", err))
		return
	}
	log.Printf("approval %s code=%s approver=%q subdomain=%s requester_ip=%q", r.Status, r.Code, approver.Email, r.Subdomain, r.RequesterIP)

	if r.Status == ApprovalApproved {
		s.writeApprovalStatus(w, http.StatusOK, "Approved",
			fmt.Sprintf("Request %s was approved. The requester's browser will be signed in to %s as you within a few seconds.",
				r.Code, s.destination(r.Subdomain, "/")))
		return
	}
	s.writeApprovalStatus(w, http.StatusOK, "Denied", fmt.Sprintf("Request %s was denied.", r.Code))
}
