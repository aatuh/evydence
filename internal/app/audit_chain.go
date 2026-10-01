package app

import (
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const auditChainEntryLegacySchemaVersion = verificationapp.AuditChainEntryLegacySchemaVersion

func canonicalAuditChainEntryHash(entry domain.AuditChainEntry) (string, error) {
	return verificationapp.CanonicalAuditChainEntryHash(verificationdomain.AuditChainEntry(entry), ledgerVerificationHasher{})
}

func verifiedAuditChainCanonicalHash(entry domain.AuditChainEntry) (string, bool, error) {
	return verificationapp.VerifiedAuditChainCanonicalHash(verificationdomain.AuditChainEntry(entry), ledgerVerificationHasher{})
}

// VerifyAuditChainEntryHash validates one immutable fact, not chain coverage,
// signature trust or an external anchor. It retains the documented v1
// PostgreSQL timestamp reconstruction instead of rejecting valid old hashes.
func VerifyAuditChainEntryHash(entry domain.AuditChainEntry) bool {
	canonical, valid, err := verifiedAuditChainCanonicalHash(entry)
	return err == nil && valid && hashBytes([]byte(entry.PreviousEntryHash+"\n"+canonical)) == entry.EntryHash
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
	if !l.verifySignatureForSubjectLocked(tenantID, batch.SignatureRefs, "merkle_batch", batch.ID, []byte(batch.RootHash)) {
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
	if !l.verifySignatureForSubjectLocked(tenantID, bundle.SignatureRefs, "release_bundle", bundle.ID, []byte(bundle.ManifestHash)) {
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
