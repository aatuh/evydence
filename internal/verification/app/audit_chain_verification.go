package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	MaxAuditChainVerificationPageEntries = 128
	MaxAuditChainVerificationBytes       = 8 << 20
)

type AuditChainVerificationView struct {
	TenantID     string
	HeadSequence int64
	HeadHash     string
	EntryCount   int64
}
type AuditSignatureBinding struct {
	Subject SubjectReference
	Payload string
}
type AuditChainVerificationPage struct {
	Entries    []verificationdomain.AuditChainEntry
	Bindings   map[string]AuditSignatureBinding
	Signatures []verificationdomain.Signature
	Keys       []verificationdomain.SigningKey
	BytesRead  int
}
type AuditChainSnapshotReader interface {
	ReadAuditChainVerificationPage(context.Context, AuditChainVerificationView, *int64, int) (AuditChainVerificationPage, error)
}
type AuditChainVerificationReader interface {
	AuditChainSnapshotReader
	LockAuditChainVerification(context.Context, string) (AuditChainVerificationView, error)
}
type AuditChainVerificationTransaction interface {
	AuditChainVerificationReader
	application.Authorizer
	verificationReceiptTransaction
}
type AuditChainVerificationTransactions interface {
	ExecuteAuditChainVerification(context.Context, func(context.Context, AuditChainVerificationTransaction) error) error
}
type AuditChainVerificationConfig struct {
	Transactions AuditChainVerificationTransactions
	Authorizer   application.Authorizer
	Hasher       CanonicalHasher
	Verifier     PayloadSignatureVerifier
	Clock        application.Clock
	IDs          application.IDGenerator
}
type AuditChainVerificationCommands struct{ config AuditChainVerificationConfig }

func NewAuditChainVerificationCommands(config AuditChainVerificationConfig) (*AuditChainVerificationCommands, error) {
	if config.Transactions == nil || config.Authorizer == nil || config.Hasher == nil || config.Verifier == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &AuditChainVerificationCommands{config}, nil
}

func (s *AuditChainVerificationCommands) VerifyAuditChain(ctx context.Context, actor identitydomain.Actor) (verificationdomain.VerificationResult, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	var result verificationdomain.VerificationResult
	err := s.config.Transactions.ExecuteAuditChainVerification(ctx, func(ctx context.Context, tx AuditChainVerificationTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, TenantWide: true}); err != nil {
			return err
		}
		view, err := tx.LockAuditChainVerification(ctx, actor.TenantID)
		if err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC()
		inspection, err := inspectAuditChainView(ctx, tx, view, actor.TenantID, now, s.config.Hasher, s.config.Verifier, nil)
		if err != nil {
			return err
		}
		result, err = persistVerificationReceipt(ctx, tx, actor, SubjectReference{TenantID: actor.TenantID, Type: "audit_chain"}, inspection, now, s.config.IDs)
		return err
	})
	if err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if verificationReturnsFailure(result.Result) {
		return cloneVerificationResult(result), ErrVerificationFailed
	}
	return cloneVerificationResult(result), nil
}

// InspectAuditChainSnapshot preserves the canonical audit/signature rules using
// only bounded page reads from one caller-owned committed view. It cannot take
// locks or persist a verification receipt. The caller controls output redaction.
func InspectAuditChainSnapshot(ctx context.Context, reader AuditChainSnapshotReader, view AuditChainVerificationView, tenant string, now time.Time, hasher CanonicalHasher, verifier PayloadSignatureVerifier) (SubjectInspection, error) {
	if err := contextError(ctx); err != nil {
		return SubjectInspection{}, err
	}
	now = now.UTC()
	if reader == nil || hasher == nil || verifier == nil || now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
		return SubjectInspection{}, ErrValidation
	}
	return inspectAuditChainView(ctx, reader, view, tenant, now, hasher, verifier, nil)
}

func inspectAuditChainView(ctx context.Context, reader AuditChainSnapshotReader, view AuditChainVerificationView, tenant string, now time.Time, hasher CanonicalHasher, verifier PayloadSignatureVerifier, collect func(verificationdomain.AuditChainEntry)) (SubjectInspection, error) {
	if view.TenantID != tenant {
		return SubjectInspection{}, ErrNotFound
	}
	if view.EntryCount < 0 || len(view.HeadHash) > 1024 || view.EntryCount == 0 && (view.HeadHash != "" || view.HeadSequence != 0) {
		return SubjectInspection{}, ErrConflict
	}
	inspector := NewAuditChainInspector(tenant, now, hasher, verifier)
	budget := MaxAuditChainVerificationBytes
	var after *int64
	for {
		if err := contextError(ctx); err != nil {
			return SubjectInspection{}, err
		}
		page, err := reader.ReadAuditChainVerificationPage(ctx, view, after, budget)
		if err != nil {
			return SubjectInspection{}, err
		}
		if len(page.Entries) > MaxAuditChainVerificationPageEntries || len(page.Bindings) > MaxAuditChainVerificationPageEntries || len(page.Signatures) > MaxAuditChainVerificationPageEntries || len(page.Keys) > MaxAuditChainVerificationPageEntries || page.BytesRead < 0 || page.BytesRead > budget || len(page.Entries) > 0 && page.BytesRead == 0 {
			return SubjectInspection{}, ErrConflict
		}
		if len(page.Entries) > 0 {
			raw, err := json.Marshal(page)
			if err != nil || len(raw) > budget {
				return SubjectInspection{}, ErrConflict
			}
			if len(raw) > page.BytesRead {
				page.BytesRead = len(raw)
			}
		}
		budget -= page.BytesRead
		if len(page.Entries) == 0 {
			break
		}
		for _, entry := range page.Entries {
			if after != nil && entry.Sequence <= *after || entry.Sequence > view.HeadSequence {
				return SubjectInspection{}, ErrConflict
			}
			if err := inspector.Append(entry, page.Bindings[entry.ID], page.Signatures, page.Keys); err != nil {
				return SubjectInspection{}, err
			}
			if collect != nil {
				collect(entry)
			}
			sequence := entry.Sequence
			after = &sequence
		}
	}
	if inspector.count != view.EntryCount || inspector.previous != view.HeadHash || after != nil && *after != view.HeadSequence {
		return SubjectInspection{}, ErrConflict
	}
	return inspector.Inspection(), nil
}

// AuditChainInspector accumulates compatible per-entry checks, not audit
// records. A reader must maintain one committed view across all pages.
type AuditChainInspector struct {
	tenant   string
	now      time.Time
	hasher   CanonicalHasher
	verifier PayloadSignatureVerifier
	previous string
	count    int64
	checks   []verificationdomain.VerifyCheck
	passed   bool
	bytes    int
}

func NewAuditChainInspector(tenant string, now time.Time, hasher CanonicalHasher, verifier PayloadSignatureVerifier) *AuditChainInspector {
	return &AuditChainInspector{tenant: tenant, now: now, hasher: hasher, verifier: verifier, passed: true}
}
func (s *AuditChainInspector) Append(e verificationdomain.AuditChainEntry, binding AuditSignatureBinding, signatures []verificationdomain.Signature, keys []verificationdomain.SigningKey) error {
	if s.hasher == nil || s.verifier == nil || len(e.ID) > 1024 {
		return ErrConflict
	}
	canonical, matches, err := VerifiedAuditChainCanonicalHash(e, s.hasher)
	validSignature := e.SignatureRef == ""
	if !validSignature && auditSignatureBindingMatches(e, binding) {
		validSignature = validReferencedPayloadSignature(binding.Subject, []string{e.SignatureRef}, signatures, keys, []byte(binding.Payload), s.now, s.verifier)
	}
	checks := []verificationdomain.VerifyCheck{}
	for _, fact := range []struct {
		name  string
		valid bool
	}{
		{"tenant_id", e.TenantID == s.tenant}, {"schema_version", e.SchemaVersion == AuditChainEntryLegacySchemaVersion || e.SchemaVersion == verificationdomain.AuditChainEntrySchemaVersion}, {"sequence", e.Sequence == s.count+1}, {"previous_hash", e.PreviousEntryHash == s.previous}, {"canonical_entry_hash", err == nil && matches}, {"entry_hash", err == nil && auditChainLinkHash(s.previous, canonical) == e.EntryHash}, {"referenced_signature", validSignature},
	} {
		value := "failed"
		if fact.valid {
			value = "passed"
		} else {
			s.passed = false
		}
		checks = append(checks, verificationdomain.VerifyCheck{Name: fact.name, Result: value, Detail: e.ID})
	}
	raw, marshalErr := json.Marshal(checks)
	if marshalErr != nil || len(raw) > MaxAuditChainVerificationBytes-s.bytes {
		return ErrConflict
	}
	s.bytes += len(raw)
	s.checks = append(s.checks, checks...)
	s.previous = e.EntryHash
	s.count++
	return nil
}

func auditSignatureBindingMatches(e verificationdomain.AuditChainEntry, b AuditSignatureBinding) bool {
	if b.Payload == "" || b.Subject.TenantID != e.TenantID {
		return false
	}
	switch e.SubjectType {
	case "release_bundle", "evidence_bundle", "merkle_batch":
		return b.Subject.Type == e.SubjectType && b.Subject.ID == e.SubjectID
	case "signing_operation":
		return b.Subject.Type != "" && b.Subject.ID != ""
	default:
		return false
	}
}
func (s *AuditChainInspector) Inspection() SubjectInspection {
	checks := append([]verificationdomain.VerifyCheck(nil), s.checks...)
	value := "failed"
	if s.passed {
		value = "passed"
	}
	checks = append(checks, verificationdomain.VerifyCheck{Name: "audit_chain", Result: value})
	required := []string{}
	seen := map[string]bool{}
	for _, check := range checks {
		if !seen[check.Name] {
			required = append(required, check.Name)
			seen[check.Name] = true
		}
	}
	return SubjectInspection{Checks: checks, Profile: verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{ID: verificationdomain.VerificationProfileAuditChainIntegrity, Version: verificationdomain.VerificationProfileSchemaVersion, RequiredChecks: required, TrustMaterial: []string{"Evydence audit-chain canonical hashes"}, IdentityPolicy: "tenant-scoped verification authorization", TransparencyProof: "not_evaluated", PayloadScope: "tenant audit-chain entries", Limitations: []string{"Audit-chain verification does not prove external anchoring or third-party log inclusion."}})}
}
