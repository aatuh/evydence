package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const ProviderSigningProfile = "evydence-provider-signing.v1"
const MaxSigningOperationIDBytes = 1024
const MaxSigningOperationChecks = 64

type SigningOperationInput struct{ ProviderID, SubjectType, SubjectID, PayloadHash string }
type SigningOperationProvider struct{ ID, TenantID, Type, Status, KeyRef string }
type SigningOperationScope struct{ TenantID, SubjectType, SubjectID string }
type ProviderSigningRequest struct {
	Profile, TenantID, ProviderID, ProviderType, ExpectedProviderType, KeyRef   string
	SubjectType, SubjectID, PayloadHash, CanonicalPayloadHash, RequestID, Nonce string
}
type ProviderSigningResult struct {
	Signature, KeyID, Algorithm, ProviderID, ProviderType, KeyRef string
	CanonicalPayloadHash, RequestID, ProviderRequestID            string
	Checks                                                        []verificationdomain.VerifyCheck
}
type ProviderSigningExecutor interface {
	SignOperation(context.Context, ProviderSigningRequest) (ProviderSigningResult, error)
}
type SigningOperationReader interface {
	ReadSigningOperationProvider(context.Context, string, string) (SigningOperationProvider, error)
	ReadSigningOperationScope(context.Context, string, string, string) (SigningOperationScope, error)
}
type SigningOperationTransaction interface {
	SigningOperationReader
	application.Authorizer
	application.AuditAppender
	InsertFocusedSigningOperation(context.Context, verificationdomain.Signature, verificationdomain.SigningOperation) error
}
type SigningOperationTransactions interface {
	ExecuteSigningOperation(context.Context, string, func(context.Context, SigningOperationTransaction) error) error
}
type SigningOperationConfig struct {
	Transactions SigningOperationTransactions
	Signer       ProviderSigningExecutor
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type SigningOperationCommands struct{ config SigningOperationConfig }

func NewSigningOperationCommands(c SigningOperationConfig) (*SigningOperationCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	// An absent executor disables this command, not unrelated runtime services.
	return &SigningOperationCommands{c}, nil
}
func operationText(v string, max int) bool {
	return len(v) <= max && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func operationID(v string) bool {
	return operationText(v, MaxSigningOperationIDBytes) && v != "" && strings.TrimSpace(v) == v
}
func operationDigest(v string) bool {
	if !strings.HasPrefix(v, "sha256:") || len(v) != 71 {
		return false
	}
	_, err := hex.DecodeString(v[7:])
	return err == nil
}
func NormalizeSigningOperationInput(in SigningOperationInput) (SigningOperationInput, error) {
	if !operationText(in.ProviderID, MaxSigningOperationIDBytes) || !operationText(in.SubjectID, MaxSigningOperationIDBytes) || !operationText(in.SubjectType, 128) || !operationText(in.PayloadHash, 128) {
		return in, ErrValidation
	}
	in.ProviderID, in.SubjectType, in.SubjectID, in.PayloadHash = strings.TrimSpace(in.ProviderID), strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID), strings.TrimSpace(in.PayloadHash)
	if !operationID(in.ProviderID) || !operationID(in.SubjectID) || !operationDigest(in.PayloadHash) {
		return in, ErrValidation
	}
	switch in.SubjectType {
	case "tenant", "product", "release", "evidence", "build", "customer_package":
	default:
		return in, ErrValidation
	}
	return in, nil
}
func ValidateSigningOperationProvider(p SigningOperationProvider, tenant, id string) error {
	if p.TenantID != tenant || p.ID != id {
		return ErrNotFound
	}
	if !operationID(p.ID) || !operationID(p.TenantID) || !validSigningProviderType(p.Type) || !operationText(p.KeyRef, 4096) || strings.TrimSpace(p.KeyRef) == "" || strings.TrimSpace(p.KeyRef) != p.KeyRef || signingProviderRefContainsSecret(p.KeyRef) {
		return ErrValidation
	}
	if p.Status != "active" {
		return ErrVerificationFailed
	}
	return nil
}
func (c *SigningOperationCommands) prepare(ctx context.Context, a identitydomain.Actor, in SigningOperationInput) (SigningOperationInput, error) {
	if c == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	if !operationID(a.TenantID) || !operationID(auditActorID(a)) {
		return in, application.ErrUnauthorized
	}
	in, err := NormalizeSigningOperationInput(in)
	if err != nil {
		return in, err
	}
	return in, c.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true})
}
func readAuthorizedSigningOperation(ctx context.Context, tx SigningOperationTransaction, a identitydomain.Actor, in SigningOperationInput) (SigningOperationProvider, error) {
	var empty SigningOperationProvider
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}); err != nil {
		return empty, err
	}
	p, err := tx.ReadSigningOperationProvider(ctx, a.TenantID, in.ProviderID)
	if err != nil {
		return empty, err
	}
	if err := ValidateSigningOperationProvider(p, a.TenantID, in.ProviderID); err != nil {
		return empty, err
	}
	s, err := tx.ReadSigningOperationScope(ctx, a.TenantID, in.SubjectType, in.SubjectID)
	if err != nil {
		return empty, err
	}
	if s.TenantID != a.TenantID || s.SubjectType != in.SubjectType || s.SubjectID != in.SubjectID || s.SubjectType == "tenant" && s.SubjectID != a.TenantID {
		return empty, ErrNotFound
	}
	return p, ctx.Err()
}
func (c *SigningOperationCommands) AuthorizeCreateSigningOperation(ctx context.Context, a identitydomain.Actor, in SigningOperationInput) error {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecuteSigningOperation(ctx, a.TenantID, func(ctx context.Context, tx SigningOperationTransaction) error {
		_, err := readAuthorizedSigningOperation(ctx, tx, a, in)
		return err
	})
}
func (c *SigningOperationCommands) CreateSigningOperation(ctx context.Context, a identitydomain.Actor, in SigningOperationInput) (verificationdomain.SigningOperation, error) {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return verificationdomain.SigningOperation{}, err
	}
	if c.config.Signer == nil {
		return verificationdomain.SigningOperation{}, ErrValidation
	}
	var out verificationdomain.SigningOperation
	err = c.config.Transactions.ExecuteSigningOperation(ctx, a.TenantID, func(ctx context.Context, tx SigningOperationTransaction) error {
		p, err := readAuthorizedSigningOperation(ctx, tx, a, in)
		if err != nil {
			return err
		}
		r := ProviderSigningRequest{Profile: ProviderSigningProfile, TenantID: a.TenantID, ProviderID: p.ID, ProviderType: p.Type, ExpectedProviderType: p.Type, KeyRef: p.KeyRef, SubjectType: in.SubjectType, SubjectID: in.SubjectID, PayloadHash: in.PayloadHash, RequestID: c.config.IDs.NewID("sreq"), Nonce: c.config.IDs.NewID("snonce")}
		r.CanonicalPayloadHash, err = CanonicalProviderSigningRequestHash(r)
		if err != nil {
			return err
		}
		signed, err := c.config.Signer.SignOperation(ctx, r)
		if err != nil {
			return err
		}
		if err := ValidateProviderSigningResult(r, signed); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		at := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		sigID, opID, auditID := c.config.IDs.NewID("sig"), c.config.IDs.NewID("sop"), c.config.IDs.NewID("ace")
		if at.IsZero() || at.Year() < 1 || at.Year() > 9999 || !operationID(sigID) || !operationID(opID) || !operationID(auditID) {
			return ErrValidation
		}
		checks := []verificationdomain.VerifyCheck{{Name: "provider_active", Result: "passed"}, {Name: "payload_hash_valid", Result: "passed"}}
		checks = append(checks, signed.Checks...)
		checks = append(checks, verificationdomain.VerifyCheck{Name: "canonical_signing_request", Result: "passed", Detail: r.Profile}, verificationdomain.VerifyCheck{Name: "signing_executor_invoked", Result: "passed", Detail: strings.TrimSpace(signed.KeyID)})
		sig := verificationdomain.Signature{ID: sigID, TenantID: a.TenantID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, KeyID: p.ID, Algorithm: strings.TrimSpace(signed.Algorithm), Value: strings.TrimSpace(signed.Signature), CreatedAt: at}
		out = verificationdomain.SigningOperation{ID: opID, TenantID: a.TenantID, ProviderID: p.ID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, PayloadHash: in.PayloadHash, CanonicalPayloadHash: r.CanonicalPayloadHash, RequestID: r.RequestID, ProviderRequestID: strings.TrimSpace(signed.ProviderRequestID), SignatureRef: sigID, Result: "passed", Checks: checks, SchemaVersion: verificationdomain.SigningOperationVersion, CreatedAt: at}
		if err := tx.InsertFocusedSigningOperation(ctx, sig, CloneSigningOperation(out)); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: auditID, TenantID: a.TenantID, EntryType: "signing_operation.created", SubjectType: "signing_operation", SubjectID: opID, ActorType: auditActorType(a), ActorID: auditActorID(a), PayloadHash: in.PayloadHash, SignatureRef: sigID, OccurredAt: at})
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return verificationdomain.SigningOperation{}, err
	}
	return CloneSigningOperation(out), nil
}
func CanonicalProviderSigningRequestHash(r ProviderSigningRequest) (string, error) {
	if r.Profile != ProviderSigningProfile || !operationID(r.TenantID) || !operationID(r.ProviderID) || !validSigningProviderType(r.ProviderType) || r.ExpectedProviderType != r.ProviderType || !operationText(r.KeyRef, 4096) || strings.TrimSpace(r.KeyRef) == "" || !operationID(r.SubjectID) || !operationDigest(r.PayloadHash) || !operationID(r.RequestID) || !operationID(r.Nonce) {
		return "", ErrValidation
	}
	if _, err := NormalizeSigningOperationInput(SigningOperationInput{ProviderID: r.ProviderID, SubjectType: r.SubjectType, SubjectID: r.SubjectID, PayloadHash: r.PayloadHash}); err != nil {
		return "", err
	}
	// Struct order and JSON field names are the existing canonical profile.
	v := struct {
		Profile      string `json:"profile"`
		TenantID     string `json:"tenant_id"`
		ProviderID   string `json:"provider_id"`
		ProviderType string `json:"provider_type"`
		KeyRef       string `json:"key_ref"`
		SubjectType  string `json:"subject_type"`
		SubjectID    string `json:"subject_id"`
		PayloadHash  string `json:"payload_hash"`
		RequestID    string `json:"request_id"`
		Nonce        string `json:"nonce"`
	}{r.Profile, r.TenantID, r.ProviderID, r.ProviderType, r.KeyRef, r.SubjectType, r.SubjectID, r.PayloadHash, r.RequestID, r.Nonce}
	body, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func ValidateProviderSigningResult(r ProviderSigningRequest, v ProviderSigningResult) error {
	if !operationText(v.Signature, 32768) || strings.TrimSpace(v.Signature) == "" || !operationText(v.Algorithm, 128) || strings.TrimSpace(v.Algorithm) == "" || !operationText(v.KeyID, 1024) || !operationText(v.ProviderRequestID, 1024) || len(v.Checks) > MaxSigningOperationChecks {
		return ErrVerificationFailed
	}
	for _, pair := range [][2]string{{v.ProviderID, r.ProviderID}, {v.ProviderType, r.ExpectedProviderType}, {v.KeyRef, r.KeyRef}, {v.CanonicalPayloadHash, r.CanonicalPayloadHash}, {v.RequestID, r.RequestID}} {
		if !operationText(pair[0], 4096) || strings.TrimSpace(pair[0]) != pair[1] {
			return ErrVerificationFailed
		}
	}
	for _, check := range v.Checks {
		if !operationText(check.Name, 128) || strings.TrimSpace(check.Name) == "" || !operationText(check.Detail, 4096) || check.Result != "passed" && check.Result != "skipped" {
			return ErrVerificationFailed
		}
	}
	return nil
}
func CloneSigningOperation(v verificationdomain.SigningOperation) verificationdomain.SigningOperation {
	v.Checks = append([]verificationdomain.VerifyCheck(nil), v.Checks...)
	return v
}
func EncodeSigningOperation(v verificationdomain.SigningOperation) ([]byte, error) {
	checks := make([]map[string]string, len(v.Checks))
	for i, c := range v.Checks {
		checks[i] = map[string]string{"name": c.Name, "result": c.Result}
		if c.Detail != "" {
			checks[i]["detail"] = c.Detail
		}
	}
	m := map[string]any{"id": v.ID, "tenant_id": v.TenantID, "provider_id": v.ProviderID, "subject_type": v.SubjectType, "subject_id": v.SubjectID, "payload_hash": v.PayloadHash, "result": v.Result, "checks": checks, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt}
	for k, text := range map[string]string{"canonical_payload_hash": v.CanonicalPayloadHash, "request_id": v.RequestID, "provider_request_id": v.ProviderRequestID, "signature_ref": v.SignatureRef} {
		if text != "" {
			m[k] = text
		}
	}
	return json.Marshal(m)
}
