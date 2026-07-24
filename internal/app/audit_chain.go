package app

import (
	"fmt"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

const auditChainEntryLegacySchemaVersion = "audit-chain-entry.v1.0.0"

func canonicalAuditChainEntryHash(entry domain.AuditChainEntry) (string, error) {
	switch entry.SchemaVersion {
	case auditChainEntryLegacySchemaVersion:
		occurredAt := entry.OccurredAt.UTC().Format(time.RFC3339Nano)
		return canonicalAnyHash(map[string]any{
			"tenant_id":           entry.TenantID,
			"sequence":            entry.Sequence,
			"entry_type":          entry.EntryType,
			"subject_type":        entry.SubjectType,
			"subject_id":          entry.SubjectID,
			"actor_type":          entry.ActorType,
			"actor_id":            entry.ActorID,
			"occurred_at":         occurredAt,
			"payload_hash":        entry.PayloadHash,
			"previous_entry_hash": entry.PreviousEntryHash,
			"signature_ref":       entry.SignatureRef,
			"schema_version":      entry.SchemaVersion,
		})
	case domain.AuditChainEntrySchemaVersion:
		occurredAt := entry.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
		return canonicalAnyHash(map[string]any{
			"id":                  entry.ID,
			"tenant_id":           entry.TenantID,
			"sequence":            entry.Sequence,
			"entry_type":          entry.EntryType,
			"subject_type":        entry.SubjectType,
			"subject_id":          entry.SubjectID,
			"actor_type":          entry.ActorType,
			"actor_id":            entry.ActorID,
			"occurred_at":         occurredAt,
			"request_id":          entry.RequestID,
			"idempotency_key":     entry.IdempotencyKey,
			"payload_hash":        entry.PayloadHash,
			"previous_entry_hash": entry.PreviousEntryHash,
			"signature_ref":       entry.SignatureRef,
			"metadata":            entry.Metadata,
			"schema_version":      entry.SchemaVersion,
		})
	default:
		return "", fmt.Errorf("unsupported audit-chain entry schema version %q", entry.SchemaVersion)
	}
}

func verifiedAuditChainCanonicalHash(entry domain.AuditChainEntry) (string, bool, error) {
	canonical, err := canonicalAuditChainEntryHash(entry)
	if err != nil || canonical == entry.CanonicalEntryHash || entry.SchemaVersion != auditChainEntryLegacySchemaVersion {
		return canonical, err == nil && canonical == entry.CanonicalEntryHash, err
	}
	// PostgreSQL retains microseconds, while historical v1 hashes could have
	// recorded nanoseconds. Reconstruct the lost sub-microsecond component
	// without relaxing verification of any other stored field.
	base := entry.OccurredAt.UTC().Truncate(time.Microsecond)
	for nanosecond := 1; nanosecond < 1000; nanosecond++ {
		candidate := entry
		candidate.OccurredAt = base.Add(time.Duration(nanosecond))
		canonical, err = canonicalAuditChainEntryHash(candidate)
		if err != nil {
			return "", false, err
		}
		if canonical == entry.CanonicalEntryHash {
			return canonical, true, nil
		}
	}
	return canonical, false, nil
}

// RehashAuditChainEntry recomputes both persisted hashes from the versioned
// canonical fields and the entry's previous hash.
func RehashAuditChainEntry(entry *domain.AuditChainEntry) error {
	canonical, err := canonicalAuditChainEntryHash(*entry)
	if err != nil {
		return err
	}
	entry.CanonicalEntryHash = canonical
	entry.EntryHash = hashBytes([]byte(entry.PreviousEntryHash + "\n" + canonical))
	return nil
}

func (l *Ledger) verifyAuditEntrySignatureLocked(entry domain.AuditChainEntry) domain.VerifyCheck {
	check := domain.VerifyCheck{Name: "referenced_signature", Detail: entry.ID}
	if entry.SignatureRef == "" {
		check.Result = "passed"
		return check
	}
	signature, ok := l.signatures[entry.SignatureRef]
	if !ok || signature.TenantID != entry.TenantID {
		check.Result = "failed"
		return check
	}
	payload, subjectType, subjectID, ok := l.auditEntrySignaturePayloadLocked(entry)
	if !ok || signature.SubjectType != subjectType || signature.SubjectID != subjectID || !l.verifySignatureLocked(entry.TenantID, []string{entry.SignatureRef}, payload) {
		check.Result = "failed"
		return check
	}
	check.Result = "passed"
	return check
}

func (l *Ledger) auditEntrySignaturePayloadLocked(entry domain.AuditChainEntry) ([]byte, string, string, bool) {
	switch entry.SubjectType {
	case "release_bundle":
		bundle, ok := l.bundles[entry.SubjectID]
		if !ok || bundle.TenantID != entry.TenantID || bundle.ManifestHash == "" {
			return nil, "", "", false
		}
		return []byte(bundle.ManifestHash), "release_bundle", bundle.ID, true
	case "evidence_bundle":
		bundle, ok := l.evidenceBundles[entry.SubjectID]
		if !ok || bundle.TenantID != entry.TenantID || bundle.ManifestHash == "" {
			return nil, "", "", false
		}
		return []byte(bundle.ManifestHash), "evidence_bundle", bundle.ID, true
	case "merkle_batch":
		batch, ok := l.merkleBatches[entry.SubjectID]
		if !ok || batch.TenantID != entry.TenantID || batch.RootHash == "" {
			return nil, "", "", false
		}
		return []byte(batch.RootHash), "merkle_batch", batch.ID, true
	case "signing_operation":
		operation, ok := l.signingOperations[entry.SubjectID]
		if !ok || operation.TenantID != entry.TenantID || operation.PayloadHash == "" {
			return nil, "", "", false
		}
		return []byte(operation.PayloadHash), operation.SubjectType, operation.SubjectID, true
	default:
		return nil, "", "", false
	}
}

func (l *Ledger) verifyMerkleAuditChainCheckpointLocked(tenantID, batchID string) ([]domain.VerifyCheck, bool) {
	batch, ok := l.merkleBatches[batchID]
	if !ok || batch.TenantID != tenantID {
		return nil, false
	}
	checks := l.verifyChainLocked(tenantID)
	entries := l.chain[tenantID]
	if batch.FromSequence < 1 || batch.ToSequence < batch.FromSequence || batch.ToSequence > int64(len(entries)) {
		return append(checks, domain.VerifyCheck{Name: "checkpoint_coverage", Result: "failed"}), true
	}
	checks = append(checks, domain.VerifyCheck{Name: "checkpoint_coverage", Result: "passed"})
	leaves := make([]string, 0, batch.ToSequence-batch.FromSequence+1)
	for _, entry := range entries[batch.FromSequence-1 : batch.ToSequence] {
		leaves = append(leaves, entry.EntryHash)
	}
	if !sameAuditChainHashes(leaves, batch.LeafHashes) || batch.EntryCount != len(leaves) || merkleRoot(leaves) != batch.RootHash {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_root", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_root", Result: "passed"})
	}
	if !l.verifySignatureLocked(tenantID, batch.SignatureRefs, []byte(batch.RootHash)) {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_signature", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_signature", Result: "passed"})
	}
	return checks, true
}

func (l *Ledger) verifyReleaseManifestAuditChainCheckpointLocked(tenantID, bundleID string) ([]domain.VerifyCheck, bool) {
	bundle, ok := l.bundles[bundleID]
	if !ok || bundle.TenantID != tenantID {
		return nil, false
	}
	checks := l.verifyChainLocked(tenantID)
	manifestHash, err := canonicalAnyHash(bundle.Manifest)
	if err != nil || manifestHash != bundle.ManifestHash {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_manifest_hash", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_manifest_hash", Result: "passed"})
	}
	if !l.verifySignatureLocked(tenantID, bundle.SignatureRefs, []byte(bundle.ManifestHash)) {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_signature", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_signature", Result: "passed"})
	}
	sequence, headHash, ok := releaseManifestAuditChainCheckpoint(bundle.Manifest)
	entries := l.chain[tenantID]
	if !ok || sequence < 0 || sequence > int64(len(entries)) || (sequence > 0 && entries[sequence-1].EntryHash != headHash) {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_coverage", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_coverage", Result: "passed"})
	}
	return checks, true
}

func sameAuditChainHashes(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func releaseManifestAuditChainCheckpoint(manifest map[string]any) (int64, string, bool) {
	raw, ok := manifest["chain_checkpoint"].(map[string]any)
	if !ok {
		return 0, "", false
	}
	var sequence int64
	switch value := raw["sequence"].(type) {
	case int:
		sequence = int64(value)
	case int64:
		sequence = value
	case float64:
		if value != float64(int64(value)) {
			return 0, "", false
		}
		sequence = int64(value)
	default:
		return 0, "", false
	}
	headHash, ok := raw["head_hash"].(string)
	if !ok {
		return 0, "", false
	}
	return sequence, headHash, true
}
