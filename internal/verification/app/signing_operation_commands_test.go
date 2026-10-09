package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var errSigningOperationFixture = errors.New("signing operation fixture failure")

type signingOperationFixture struct {
	provider   SigningOperationProvider
	scope      SigningOperationScope
	phase      string
	request    ProviderSigningRequest
	calls      int
	records    []verificationdomain.SigningOperation
	signatures []verificationdomain.Signature
	audits     []application.AuditEvent
	cancel     context.CancelFunc
}

func (f *signingOperationFixture) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.phase == "authorization" || r.Scope != ScopeKeysAdmin || !r.TenantWide {
		return application.ErrForbidden
	}
	return nil
}
func (f *signingOperationFixture) ExecuteSigningOperation(ctx context.Context, _ string, fn func(context.Context, SigningOperationTransaction) error) error {
	n, m, k := len(f.records), len(f.signatures), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errSigningOperationFixture
	}
	if err != nil {
		f.records, f.signatures, f.audits = f.records[:n], f.signatures[:m], f.audits[:k]
	}
	return err
}
func (f *signingOperationFixture) ReadSigningOperationProvider(context.Context, string, string) (SigningOperationProvider, error) {
	if f.phase == "provider" {
		return SigningOperationProvider{}, errSigningOperationFixture
	}
	return f.provider, nil
}
func (f *signingOperationFixture) ReadSigningOperationScope(context.Context, string, string, string) (SigningOperationScope, error) {
	if f.phase == "scope" {
		return SigningOperationScope{}, errSigningOperationFixture
	}
	return f.scope, nil
}
func (f *signingOperationFixture) SignOperation(_ context.Context, r ProviderSigningRequest) (ProviderSigningResult, error) {
	f.calls++
	f.request = r
	if f.phase == "signer" {
		return ProviderSigningResult{}, errSigningOperationFixture
	}
	v := ProviderSigningResult{Signature: "signature", Algorithm: "external-aws_kms", KeyID: "public-key-reference", ProviderID: r.ProviderID, ProviderType: r.ProviderType, KeyRef: r.KeyRef, CanonicalPayloadHash: r.CanonicalPayloadHash, RequestID: r.RequestID, ProviderRequestID: "receipt", Checks: []verificationdomain.VerifyCheck{{Name: "executor", Result: "passed"}}}
	switch f.phase {
	case "mismatched receipt":
		v.RequestID = "another"
	case "failed check":
		v.Checks[0].Result = "failed"
	case "oversized receipt":
		v.Signature = strings.Repeat("s", 32769)
	case "oversized checks":
		v.Checks = make([]verificationdomain.VerifyCheck, 65)
	case "cancel after signer":
		f.cancel()
	}
	return v, nil
}
func (f *signingOperationFixture) InsertFocusedSigningOperation(_ context.Context, s verificationdomain.Signature, v verificationdomain.SigningOperation) error {
	if f.phase == "insert" {
		return errSigningOperationFixture
	}
	f.signatures = append(f.signatures, s)
	f.records = append(f.records, v)
	return nil
}
func (f *signingOperationFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errSigningOperationFixture
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel after audit" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func signingOperationCommandFixture(t *testing.T) (*SigningOperationCommands, *signingOperationFixture, identitydomain.Actor, SigningOperationInput) {
	t.Helper()
	f := &signingOperationFixture{provider: SigningOperationProvider{TenantID: "tenant", ID: "provider", Type: "aws_kms", Status: "active", KeyRef: "key"}, scope: SigningOperationScope{TenantID: "tenant", SubjectType: "release", SubjectID: "release"}}
	n := 0
	c, err := NewSigningOperationCommands(SigningOperationConfig{Transactions: f, Signer: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 4, 8, 0, 0, 987654321, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}, SigningOperationInput{ProviderID: "provider", SubjectType: "release", SubjectID: "release", PayloadHash: "sha256:" + strings.Repeat("A", 64)}
}
func TestSigningOperationCommandsBindCanonicalReceiptAndGuardReplayWithoutSigning(t *testing.T) {
	c, f, a, in := signingOperationCommandFixture(t)
	if err := c.AuthorizeCreateSigningOperation(t.Context(), a, in); err != nil || f.calls != 0 || len(f.records) != 0 {
		t.Fatal("replay guard signed or wrote", err)
	}
	v, err := c.CreateSigningOperation(t.Context(), a, in)
	if err != nil || v.Result != "passed" || v.RequestID != f.request.RequestID || v.CanonicalPayloadHash != f.request.CanonicalPayloadHash || v.CreatedAt.Nanosecond() != 987654000 || len(f.records) != 1 || len(f.signatures) != 1 || len(f.audits) != 1 {
		t.Fatal("operation contract differs", v, err)
	}
	if f.audits[0].PayloadHash != in.PayloadHash || f.audits[0].SignatureRef != v.SignatureRef || f.audits[0].SubjectID != v.ID {
		t.Fatal("operation audit is not bound to receipt")
	}
	want := `{"profile":"evydence-provider-signing.v1","tenant_id":"tenant","provider_id":"provider","provider_type":"aws_kms","key_ref":"key","subject_type":"release","subject_id":"release","payload_hash":"` + in.PayloadHash + `","request_id":"sreq-1","nonce":"snonce-2"}`
	sum := sha256.Sum256([]byte(want))
	if v.CanonicalPayloadHash != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("canonical request bytes changed", v.CanonicalPayloadHash)
	}
	v.Checks[0].Result = "changed"
	if f.records[0].Checks[0].Result == "changed" {
		t.Fatal("returned checks alias persisted receipt")
	}
	raw, err := EncodeSigningOperation(f.records[0])
	if err != nil || !strings.Contains(string(raw), `"provider_request_id":"receipt"`) || strings.Contains(string(raw), "KeyRef") || strings.Contains(string(raw), `"Signature"`) {
		t.Fatal("operation response exposed internal signing material", string(raw), err)
	}
	empty := f.records[0]
	empty.ProviderRequestID = ""
	raw, err = EncodeSigningOperation(empty)
	if err != nil || strings.Contains(string(raw), `"provider_request_id"`) {
		t.Fatal("empty provider receipt ID no longer omitted", err)
	}
}
func TestSigningOperationCommandsFailuresLeaveNoReceiptOrAudit(t *testing.T) {
	for _, phase := range []string{"authorization", "provider", "scope", "foreign provider", "foreign scope", "inactive", "signer", "mismatched receipt", "failed check", "oversized receipt", "oversized checks", "insert", "audit", "commit", "cancel", "cancel after signer", "cancel after audit"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := signingOperationCommandFixture(t)
			f.phase = phase
			switch phase {
			case "foreign provider":
				f.provider.TenantID = "other"
			case "foreign scope":
				f.scope.SubjectID = "other"
			case "inactive":
				f.provider.Status = "revoked"
			}
			ctx := t.Context()
			if strings.HasPrefix(phase, "cancel after") {
				ctx, f.cancel = context.WithCancel(ctx)
				defer f.cancel()
			}
			if phase == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			v, err := c.CreateSigningOperation(ctx, a, in)
			if err == nil || !reflect.DeepEqual(v, verificationdomain.SigningOperation{}) || len(f.records)+len(f.signatures)+len(f.audits) != 0 {
				t.Fatal("failed operation escaped", v, err)
			}
			if phase == "authorization" || phase == "provider" || phase == "scope" || phase == "foreign provider" || phase == "foreign scope" || phase == "inactive" || phase == "cancel" {
				if f.calls != 0 {
					t.Fatal("invalid state invoked signer")
				}
			}
		})
	}
}
func TestSigningOperationInputRawBounds(t *testing.T) {
	_, _, _, valid := signingOperationCommandFixture(t)
	for _, field := range []string{"provider", "subject", "type", "hash", "nul", "utf8"} {
		in := valid
		switch field {
		case "provider":
			in.ProviderID = strings.Repeat(" ", 1025) + in.ProviderID
		case "subject":
			in.SubjectID = strings.Repeat(" ", 1025) + in.SubjectID
		case "type":
			in.SubjectType = strings.Repeat(" ", 129) + in.SubjectType
		case "hash":
			in.PayloadHash = strings.Repeat(" ", 129) + in.PayloadHash
		case "nul":
			in.SubjectID += "\x00"
		case "utf8":
			in.SubjectID = string([]byte{255})
		}
		if _, err := NormalizeSigningOperationInput(in); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid raw input accepted", field, err)
		}
	}
}

func TestSigningOperationReceiptBindsEveryProviderCoordinateAndBoundsOutput(t *testing.T) {
	c, f, a, in := signingOperationCommandFixture(t)
	if _, err := c.CreateSigningOperation(t.Context(), a, in); err != nil {
		t.Fatal(err)
	}
	r := f.request
	valid, err := f.SignOperation(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ProviderSigningResult){
		"provider":             func(v *ProviderSigningResult) { v.ProviderID = "other" },
		"type":                 func(v *ProviderSigningResult) { v.ProviderType = "gcp_kms" },
		"key":                  func(v *ProviderSigningResult) { v.KeyRef = "other" },
		"canonical commitment": func(v *ProviderSigningResult) { v.CanonicalPayloadHash = "sha256:" + strings.Repeat("0", 64) },
		"request":              func(v *ProviderSigningResult) { v.RequestID = "other" },
		"signature NUL":        func(v *ProviderSigningResult) { v.Signature = "sig\x00" },
		"signature UTF8":       func(v *ProviderSigningResult) { v.Signature = string([]byte{255}) },
		"algorithm":            func(v *ProviderSigningResult) { v.Algorithm = strings.Repeat("a", 129) },
		"provider receipt ID":  func(v *ProviderSigningResult) { v.ProviderRequestID = strings.Repeat("i", 1025) },
		"executor key ID":      func(v *ProviderSigningResult) { v.KeyID = strings.Repeat("i", 1025) },
		"check name":           func(v *ProviderSigningResult) { v.Checks[0].Name = " " },
		"check state":          func(v *ProviderSigningResult) { v.Checks[0].Result = "unknown" },
		"check detail":         func(v *ProviderSigningResult) { v.Checks[0].Detail = strings.Repeat("d", 4097) },
	} {
		t.Run(name, func(t *testing.T) {
			v := valid
			v.Checks = append([]verificationdomain.VerifyCheck(nil), valid.Checks...)
			mutate(&v)
			if !errors.Is(ValidateProviderSigningResult(r, v), ErrVerificationFailed) {
				t.Fatal("unsafe or unbound provider receipt accepted")
			}
		})
	}
}
func TestSigningOperationConfigAllowsDisabledExecutorButRequiresCorePorts(t *testing.T) {
	c, f, a, in := signingOperationCommandFixture(t)
	for _, field := range []string{"transactions", "authorizer", "clock", "IDs"} {
		cfg := c.config
		switch field {
		case "transactions":
			cfg.Transactions = nil
		case "authorizer":
			cfg.Authorizer = nil
		case "clock":
			cfg.Clock = nil
		case "IDs":
			cfg.IDs = nil
		}
		if _, err := NewSigningOperationCommands(cfg); !errors.Is(err, ErrValidation) {
			t.Fatal("incomplete config accepted", field)
		}
	}
	cfg := c.config
	cfg.Signer = nil
	disabled, err := NewSigningOperationCommands(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := disabled.CreateSigningOperation(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || f.calls != 0 || len(f.records) != 0 {
		t.Fatal("disabled executor created a receipt", err)
	}
}
