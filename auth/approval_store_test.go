package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

func TestNewApprovalCode(t *testing.T) {
	re := regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		c, err := newApprovalCode()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(c) {
			t.Fatalf("code %q has unexpected form", c)
		}
		if normalizeApprovalCode(c) != c {
			t.Fatalf("normalize(%q) != itself", c)
		}
		seen[c] = true
	}
	if len(seen) < 999 {
		t.Errorf("too many collisions: %d unique of 1000", len(seen))
	}
}

func TestNormalizeApprovalCode(t *testing.T) {
	tests := map[string]string{
		"KDFX-7QMP":   "KDFX-7QMP",
		"kdfx7qmp":    "KDFX-7QMP",
		" kdfx 7qmp ": "KDFX-7QMP",
		"OIL0-1234":   "0110-1234", // O→0, I/L→1
		"KDFX-7QM":    "",
		"KDFX-7QMPX":  "",
		"KDFX-7QMU":   "", // U は使わない
		"KDFX/7QMP":   "",
		"":            "",
	}
	for in, want := range tests {
		if got := normalizeApprovalCode(in); got != want {
			t.Errorf("normalizeApprovalCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMemoryApprovalStore(t *testing.T) {
	ctx := context.Background()
	m := newMemoryApprovalStore()
	r := &ApprovalRequest{Code: "AAAA-BBBB", Status: ApprovalPending}
	if err := m.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, r); !errors.Is(err, ErrApprovalConflict) {
		t.Errorf("duplicate create: err = %v", err)
	}
	got, etag, err := m.Get(ctx, "AAAA-BBBB")
	if err != nil || got.Status != ApprovalPending {
		t.Fatalf("get = %+v, %v", got, err)
	}
	got.Status = ApprovalApproved
	if err := m.Update(ctx, got, etag); err != nil {
		t.Fatal(err)
	}
	// 古い etag での更新は失敗する（1回限り）
	got.Status = ApprovalConsumed
	if err := m.Update(ctx, got, etag); !errors.Is(err, ErrApprovalConflict) {
		t.Errorf("stale update: err = %v", err)
	}
	if _, _, err := m.Get(ctx, "ZZZZ-ZZZZ"); !errors.Is(err, ErrApprovalNotFound) {
		t.Errorf("missing: err = %v", err)
	}
}

type fakeS3 struct {
	lastPut *s3.PutObjectInput
	putErr  error
	getErr  error
	getBody string
}

func (f *fakeS3) PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.lastPut = in
	return &s3.PutObjectOutput{}, f.putErr
}

func (f *fakeS3) GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader([]byte(f.getBody))), ETag: aws.String(`"etag1"`)}, nil
}

func TestS3ApprovalStore(t *testing.T) {
	ctx := context.Background()
	f := &fakeS3{}
	s := &s3ApprovalStore{client: f, bucket: "bucket", prefix: "approvals/"}
	r := &ApprovalRequest{Code: "AAAA-BBBB", Status: ApprovalPending}

	if err := s.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if aws.ToString(f.lastPut.Key) != "approvals/AAAA-BBBB.json" || aws.ToString(f.lastPut.IfNoneMatch) != "*" || f.lastPut.IfMatch != nil {
		t.Errorf("create put = key %q if-none-match %v if-match %v", aws.ToString(f.lastPut.Key), f.lastPut.IfNoneMatch, f.lastPut.IfMatch)
	}
	if err := s.Update(ctx, r, `"etag1"`); err != nil {
		t.Fatal(err)
	}
	if aws.ToString(f.lastPut.IfMatch) != `"etag1"` || f.lastPut.IfNoneMatch != nil {
		t.Errorf("update put = if-match %v if-none-match %v", f.lastPut.IfMatch, f.lastPut.IfNoneMatch)
	}

	for _, code := range []string{"PreconditionFailed", "ConditionalRequestConflict"} {
		f.putErr = &smithy.GenericAPIError{Code: code}
		if err := s.Update(ctx, r, `"etag1"`); !errors.Is(err, ErrApprovalConflict) {
			t.Errorf("%s: err = %v", code, err)
		}
	}
	f.putErr = &smithy.GenericAPIError{Code: "AccessDenied"}
	if err := s.Create(ctx, r); err == nil || errors.Is(err, ErrApprovalConflict) {
		t.Errorf("AccessDenied on put must be a plain error, got %v", err)
	}

	f.getBody = `{"code":"AAAA-BBBB","status":"approved","approver_email":"a@example.com"}`
	got, etag, err := s.Get(ctx, "AAAA-BBBB")
	if err != nil || got.Status != ApprovalApproved || got.ApproverEmail != "a@example.com" || etag != `"etag1"` {
		t.Errorf("get = %+v %q %v", got, etag, err)
	}
	f.getErr = &types.NoSuchKey{}
	if _, _, err := s.Get(ctx, "AAAA-BBBB"); !errors.Is(err, ErrApprovalNotFound) {
		t.Errorf("NoSuchKey: err = %v", err)
	}
}
