package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/pkg/errors"
)

// 承認の要求の状態
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalConsumed = "consumed" // 申請者のブラウザがセッションを受け取った（もう使えない）
)

// ApprovalRequest は承認の要求。保留中は ApprovalStore に置く。
type ApprovalRequest struct {
	Code        string    `json:"code"`        // 申請者に見せ、承認者が入力するコード（例: KDFX-7QMP）
	SecretHash  string    `json:"secret_hash"` // 申請者のブラウザの cookie に入れた秘密の値の SHA-256（hex）
	Subdomain   string    `json:"subdomain"`   // 行き先（承認されたセッションはここだけで有効）
	Path        string    `json:"path"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RequesterIP string    `json:"requester_ip"`
	RequesterUA string    `json:"requester_ua"`

	Status        string    `json:"status"`
	ApproverEmail string    `json:"approver_email,omitempty"`
	DecidedAt     time.Time `json:"decided_at,omitempty"`
}

var (
	ErrApprovalNotFound = errors.New("approval request not found")
	ErrApprovalConflict = errors.New("approval request was changed concurrently")
)

// ApprovalStore は承認の要求を置く場所。Update は Get で得た etag のときだけ成功する（1回限りにするため）。
type ApprovalStore interface {
	// Create は新しい要求を置く。同じコードの要求がすでにあれば ErrApprovalConflict。
	Create(ctx context.Context, r *ApprovalRequest) error
	Get(ctx context.Context, code string) (*ApprovalRequest, string, error)
	// Update は etag が変わっていなければ要求を書き換える。変わっていれば ErrApprovalConflict。
	Update(ctx context.Context, r *ApprovalRequest, etag string) error
}

// コードに使う文字（Crockford の Base32。I L O U を含まない）
const approvalCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newApprovalCode は "XXXX-XXXX" 形式のランダムなコードを作る（40 ビット）。
func newApprovalCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, approvalCodeAlphabet[int(c)%len(approvalCodeAlphabet)]) // 256 は 32 で割り切れるので偏らない
	}
	return string(out), nil
}

// normalizeApprovalCode は入力されたコードを "XXXX-XXXX" に整える。形が合わなければ "" を返す。
// 空白・ハイフンは無視し、読み違えやすい文字（O→0、I/L→1）は Crockford の規則で読み替える。
func normalizeApprovalCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case ' ', '-', '\t':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(approvalCodeAlphabet, r) {
			return ""
		}
		b.WriteRune(r)
	}
	c := b.String()
	if len(c) != 8 {
		return ""
	}
	return c[:4] + "-" + c[4:]
}

// --- S3 ---

type s3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type s3ApprovalStore struct {
	client s3API
	bucket string
	prefix string
}

// NewS3ApprovalStore は bucket の approvals/ の下に要求を置く ApprovalStore を作る。
// 古い要求はライフサイクルルールで消すこと（アプリ側でも ExpiresAt を確かめる）。
func NewS3ApprovalStore(client *s3.Client, bucket string) ApprovalStore {
	return &s3ApprovalStore{client: client, bucket: bucket, prefix: "approvals/"}
}

func (s *s3ApprovalStore) key(code string) string { return s.prefix + code + ".json" }

func (s *s3ApprovalStore) put(ctx context.Context, r *ApprovalRequest, ifMatch, ifNoneMatch *string) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s.key(r.Code)),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
		IfMatch:     ifMatch,
		IfNoneMatch: ifNoneMatch,
	})
	if isS3PreconditionError(err) {
		return ErrApprovalConflict
	}
	return err
}

func (s *s3ApprovalStore) Create(ctx context.Context, r *ApprovalRequest) error {
	return s.put(ctx, r, nil, aws.String("*"))
}

func (s *s3ApprovalStore) Update(ctx context.Context, r *ApprovalRequest, etag string) error {
	return s.put(ctx, r, aws.String(etag), nil)
}

func (s *s3ApprovalStore) Get(ctx context.Context, code string) (*ApprovalRequest, string, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(code)),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		var apiErr smithy.APIError
		if errors.As(err, &nsk) || (errors.As(err, &apiErr) && (apiErr.ErrorCode() == "NoSuchKey" || apiErr.ErrorCode() == "AccessDenied")) {
			// AccessDenied: ListBucket 権限がないと、存在しないキーは 403 になる
			return nil, "", ErrApprovalNotFound
		}
		return nil, "", err
	}
	defer out.Body.Close()
	body, err := io.ReadAll(io.LimitReader(out.Body, 64*1024))
	if err != nil {
		return nil, "", err
	}
	var r ApprovalRequest
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, "", errors.Wrap(err, "broken approval request")
	}
	return &r, aws.ToString(out.ETag), nil
}

func isS3PreconditionError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "PreconditionFailed", "ConditionalRequestConflict":
			return true
		}
	}
	return false
}

// --- メモリ（テスト用） ---

type memoryApprovalStore struct {
	mu    sync.Mutex
	items map[string]memoryApprovalItem
	seq   int
}

type memoryApprovalItem struct {
	data []byte
	etag string
}

func newMemoryApprovalStore() *memoryApprovalStore {
	return &memoryApprovalStore{items: map[string]memoryApprovalItem{}}
}

func (m *memoryApprovalStore) store(r *ApprovalRequest) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	m.seq++
	m.items[r.Code] = memoryApprovalItem{data: data, etag: fmt.Sprintf(`"%d"`, m.seq)}
	return nil
}

func (m *memoryApprovalStore) Create(ctx context.Context, r *ApprovalRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[r.Code]; ok {
		return ErrApprovalConflict
	}
	return m.store(r)
}

func (m *memoryApprovalStore) Update(ctx context.Context, r *ApprovalRequest, etag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[r.Code]
	if !ok || item.etag != etag {
		return ErrApprovalConflict
	}
	return m.store(r)
}

func (m *memoryApprovalStore) Get(ctx context.Context, code string) (*ApprovalRequest, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.items[code]
	if !ok {
		return nil, "", ErrApprovalNotFound
	}
	var r ApprovalRequest
	if err := json.Unmarshal(item.data, &r); err != nil {
		return nil, "", err
	}
	return &r, item.etag, nil
}
