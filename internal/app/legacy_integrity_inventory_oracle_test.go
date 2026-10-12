package app

import "github.com/aatuh/evydence/internal/domain"

// Cached chain inspection and inventory counts are historical characterization.
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

func (l *Ledger) resourceCountsLocked(tenantID string) map[string]int {
	counts := map[string]int{
		"audit_chain_entries":       len(l.chain[tenantID]),
		"artifact_signatures":       0,
		"cosign_verifications":      0,
		"evidence":                  0,
		"merkle_batches":            0,
		"object_retention_policies": 0,
		"release_bundles":           0,
		"transparency_checkpoints":  0,
	}
	for _, item := range l.evidence {
		if item.TenantID == tenantID {
			counts["evidence"]++
		}
	}
	for _, bundle := range l.bundles {
		if bundle.TenantID == tenantID {
			counts["release_bundles"]++
		}
	}
	for _, sig := range l.artifactSigs {
		if sig.TenantID == tenantID {
			counts["artifact_signatures"]++
		}
	}
	for _, verification := range l.cosignVerifs {
		if verification.TenantID == tenantID {
			counts["cosign_verifications"]++
		}
	}
	for _, batch := range l.merkleBatches {
		if batch.TenantID == tenantID {
			counts["merkle_batches"]++
		}
	}
	for _, checkpoint := range l.transparency {
		if checkpoint.TenantID == tenantID {
			counts["transparency_checkpoints"]++
		}
	}
	for _, policy := range l.retentionPolicies {
		if policy.TenantID == tenantID {
			counts["object_retention_policies"]++
		}
	}
	return counts
}

func (l *Ledger) verifyChainLocked(tenantID string) []domain.VerifyCheck {
	entries := l.chain[tenantID]
	checks := []domain.VerifyCheck{}
	previous := ""
	passed := true
	for i, entry := range entries {
		if entry.TenantID != tenantID {
			checks = append(checks, domain.VerifyCheck{Name: "tenant_id", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "tenant_id", Result: "passed", Detail: entry.ID})
		}
		if entry.SchemaVersion != auditChainEntryLegacySchemaVersion && entry.SchemaVersion != domain.AuditChainEntrySchemaVersion {
			checks = append(checks, domain.VerifyCheck{Name: "schema_version", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "schema_version", Result: "passed", Detail: entry.ID})
		}
		if entry.Sequence != int64(i+1) {
			checks = append(checks, domain.VerifyCheck{Name: "sequence", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "sequence", Result: "passed", Detail: entry.ID})
		}
		if entry.PreviousEntryHash != previous {
			checks = append(checks, domain.VerifyCheck{Name: "previous_hash", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "previous_hash", Result: "passed", Detail: entry.ID})
		}
		canonical, canonicalMatches, err := verifiedAuditChainCanonicalHash(entry)
		if err != nil || !canonicalMatches {
			checks = append(checks, domain.VerifyCheck{Name: "canonical_entry_hash", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "canonical_entry_hash", Result: "passed", Detail: entry.ID})
		}
		if err != nil || hashBytes([]byte(previous+"\n"+canonical)) != entry.EntryHash {
			checks = append(checks, domain.VerifyCheck{Name: "entry_hash", Result: "failed", Detail: entry.ID})
			passed = false
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "entry_hash", Result: "passed", Detail: entry.ID})
		}
		signatureCheck := l.verifyAuditEntrySignatureLocked(entry)
		checks = append(checks, signatureCheck)
		if signatureCheck.Result != "passed" {
			passed = false
		}
		previous = entry.EntryHash
	}
	if passed {
		checks = append(checks, domain.VerifyCheck{Name: "audit_chain", Result: "passed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "audit_chain", Result: "failed"})
	}
	return checks
}
