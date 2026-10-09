package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sort"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type memoryCustomerAuditHasher struct{}

func (memoryCustomerAuditHasher) Hash(v any) (string, error) {
	return application.NormalizedJSONHash(v)
}

// A public-material-only verifier for the typed fixture backend. Native
// composition supplies its own adapter; no private key or signer is involved.
type memoryCustomerPayloadVerifier struct{}

func (memoryCustomerPayloadVerifier) VerifyPayload(public, signature string, payload []byte) bool {
	if len(public) > 128 || len(signature) > 128 {
		return false
	}
	key, err := base64.RawStdEncoding.DecodeString(public)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.RawStdEncoding.DecodeString(signature)
	return err == nil && ed25519.Verify(ed25519.PublicKey(key), payload, sig)
}

type memoryCustomerAuditPages struct {
	rows    *MemoryUnitOfWorkSnapshot
	tenant  string
	indices []int
}

func readMemoryCustomerPackageAudit(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, at time.Time, budget *memoryCustomerSnapshotBudget, hasher verificationapp.CanonicalHasher, verifier verificationapp.PayloadSignatureVerifier) (map[string]any, error) {
	if err := validateMemoryCustomerSnapshotRead(ctx, s, tenant, product, release, budget); err != nil {
		return nil, err
	}
	at = at.UTC()
	if at.IsZero() || at.Year() < 1 || at.Year() > 9999 || hasher == nil || verifier == nil {
		return nil, ErrValidation
	}
	entries := s.AuditEntries[tenant]
	// An encoded audit row necessarily exceeds 64 bytes. This cheap source
	// bound prevents an unbounded index allocation before paged byte checks.
	if len(entries) > verificationapp.MaxAuditChainVerificationBytes/64 {
		return nil, ErrConflict
	}
	view := verificationapp.AuditChainVerificationView{TenantID: tenant, EntryCount: int64(len(entries))}
	indices := make([]int, 0, len(entries))
	for i, e := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e.TenantID != tenant {
			return nil, ErrConflict
		}
		indices = append(indices, i)
		if e.Sequence > view.HeadSequence {
			view.HeadSequence, view.HeadHash = e.Sequence, e.EntryHash
		}
	}
	if len(view.HeadHash) > 1024 {
		return nil, ErrConflict
	}
	sort.Slice(indices, func(i, j int) bool { return entries[indices[i]].Sequence < entries[indices[j]].Sequence })
	inspection, err := verificationapp.InspectAuditChainSnapshot(ctx, memoryCustomerAuditPages{s, tenant, indices}, view, tenant, at, hasher, verifier)
	if err != nil {
		return nil, err
	}
	result := "passed"
	for _, c := range inspection.Checks {
		if c.Result == "failed" {
			result = "failed"
			break
		}
	}
	out := map[string]any{"result": result, "latest_sequence": view.EntryCount, "head_hash": view.HeadHash, "checks": []map[string]any{{"name": "audit_chain_integrity", "result": result}}}
	working := *budget
	if err := working.charge(out); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*budget = working
	return out, nil
}

func (r memoryCustomerAuditPages) ReadAuditChainVerificationPage(ctx context.Context, view verificationapp.AuditChainVerificationView, after *int64, maxBytes int) (verificationapp.AuditChainVerificationPage, error) {
	var empty verificationapp.AuditChainVerificationPage
	if ctx == nil || r.rows == nil || maxBytes < 0 || maxBytes > verificationapp.MaxAuditChainVerificationBytes {
		return empty, ErrValidation
	}
	if view.TenantID != r.tenant {
		return empty, ErrNotFound
	}
	working := memoryCustomerSnapshotBudget{remainingBytes: maxBytes}
	page := verificationapp.AuditChainVerificationPage{Bindings: map[string]verificationapp.AuditSignatureBinding{}}
	refs := map[string]bool{}
	for _, i := range r.indices {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		e := r.rows.AuditEntries[r.tenant][i]
		if after != nil && e.Sequence <= *after || e.Sequence > view.HeadSequence {
			continue
		}
		if len(page.Entries) == verificationapp.MaxAuditChainVerificationPageEntries {
			break
		}
		if !memoryCustomerSnapshotID(e.ID, false) || e.TenantID != r.tenant || len(e.SignatureRef) > 1024 || len(e.SubjectID) > 1024 {
			return empty, ErrConflict
		}
		if _, err := memoryCustomerSnapshotTime(e.OccurredAt); err != nil {
			return empty, err
		}
		// Canonical private metadata is bounded but not redacted or normalized:
		// the inspector needs exactly the recorded versioned hash inputs.
		row := map[string]any{"id": e.ID, "tenant_id": e.TenantID, "sequence": e.Sequence, "entry_type": e.EntryType, "subject_type": e.SubjectType, "subject_id": e.SubjectID, "actor_type": e.ActorType, "actor_id": e.ActorID, "occurred_at": e.OccurredAt.UTC().Format(time.RFC3339Nano), "request_id": e.RequestID, "idempotency_key": e.IdempotencyKey, "payload_hash": e.PayloadHash, "canonical_entry_hash": e.CanonicalEntryHash, "previous_entry_hash": e.PreviousEntryHash, "entry_hash": e.EntryHash, "signature_ref": e.SignatureRef, "metadata": e.Metadata, "schema_version": e.SchemaVersion}
		if err := working.charge(row); err != nil {
			return empty, err
		}
		page.Entries = append(page.Entries, verificationdomain.AuditChainEntry(e))
		if e.SignatureRef != "" {
			refs[e.SignatureRef] = true
			binding, ok := memoryCustomerAuditBinding(r.rows, e)
			if ok {
				if len(binding.Payload) > 1024 || len(binding.Subject.ID) > 1024 || len(binding.Subject.Type) > 64 {
					return empty, ErrConflict
				}
				raw, err := json.Marshal(binding)
				if err != nil || working.chargeJSON(raw) != nil {
					return empty, ErrConflict
				}
				page.Bindings[e.ID] = binding
			}
		}
	}
	keys := map[string]bool{}
	for ref := range refs {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		sig, ok := r.rows.Signatures[ref]
		if !ok || sig.ID != ref || sig.TenantID != r.tenant {
			continue
		}
		if !memoryGovernanceText(sig.Value, maxBytes) || len(sig.KeyID) > 1024 {
			return empty, ErrConflict
		}
		public := verificationdomain.Signature(sig)
		raw, err := json.Marshal(public)
		if err != nil || working.chargeJSON(raw) != nil {
			return empty, ErrConflict
		}
		page.Signatures = append(page.Signatures, public)
		k, ok := r.rows.SigningKeys[sig.KeyID]
		if !ok || k.ID != sig.KeyID || k.TenantID != r.tenant || keys[k.ID] {
			continue
		}
		statusValue := k.Status
		if statusValue == "" {
			statusValue = verificationdomain.SigningKeyStatusLegacyUnspecifiedValue
		}
		status, err := verificationdomain.ParseSigningKeyStatus(statusValue)
		if err != nil {
			return empty, ErrConflict
		}
		if !memoryGovernanceText(k.PublicKey, maxBytes) {
			return empty, ErrConflict
		}
		key := verificationdomain.SigningKey{ID: k.ID, TenantID: k.TenantID, KID: k.KID, Version: k.Version, Provider: k.Provider, Algorithm: k.Algorithm, Status: status, PublicKey: k.PublicKey, PublicKeyFingerprint: k.PublicKeyFingerprint, ValidFrom: k.ValidFrom, ValidUntil: cloneTimePtr(k.ValidUntil), CreatedAt: k.CreatedAt, RevokedAt: cloneTimePtr(k.RevokedAt), RevocationReason: k.RevocationReason, RevocationSemantics: k.RevocationSemantics, HistoricalValidityPolicy: k.HistoricalValidityPolicy, CompromisedAt: cloneTimePtr(k.CompromisedAt)}
		raw, err = json.Marshal(key)
		if err != nil || working.chargeJSON(raw) != nil {
			return empty, ErrConflict
		}
		page.Keys = append(page.Keys, key)
		keys[k.ID] = true
	}
	page.BytesRead = maxBytes - working.remainingBytes
	return page, nil
}

func memoryCustomerAuditBinding(s *MemoryUnitOfWorkSnapshot, e domain.AuditChainEntry) (verificationapp.AuditSignatureBinding, bool) {
	b := verificationapp.AuditSignatureBinding{Subject: verificationapp.SubjectReference{TenantID: e.TenantID, Type: e.SubjectType, ID: e.SubjectID}}
	switch e.SubjectType {
	case "release_bundle":
		v, ok := s.ReleaseBundles[e.SubjectID]
		if !ok || v.ID != e.SubjectID || v.TenantID != e.TenantID {
			return b, false
		}
		b.Payload = v.ManifestHash
	case "evidence_bundle":
		v, ok := s.EvidenceBundles[e.SubjectID]
		if !ok || v.ID != e.SubjectID || v.TenantID != e.TenantID {
			return b, false
		}
		b.Payload = v.ManifestHash
	case "merkle_batch":
		v, ok := s.MerkleBatches[e.SubjectID]
		if !ok || v.ID != e.SubjectID || v.TenantID != e.TenantID {
			return b, false
		}
		b.Payload = v.RootHash
	case "signing_operation":
		v, ok := s.SigningOperations[e.SubjectID]
		if !ok || v.ID != e.SubjectID || v.TenantID != e.TenantID {
			return b, false
		}
		b.Payload = v.PayloadHash
		b.Subject.Type, b.Subject.ID = v.SubjectType, v.SubjectID
	default:
		return b, false
	}
	return b, true
}
