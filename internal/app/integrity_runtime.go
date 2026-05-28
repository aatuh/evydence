package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type VerifyCosignInput struct {
	ArtifactSignatureID string
	RekorUUID           string
	RekorLogIndex       string
	CertificateIdentity string
	CertificateIssuer   string
}

type CreateSigningProviderInput struct {
	Name      string
	Type      string
	KeyRef    string
	Encrypted bool
}

type CreateMerkleBatchInput struct {
	FromSequence int64
	ToSequence   int64
}

type CreateTransparencyCheckpointInput struct {
	BatchID     string
	Provider    string
	ExternalURL string
	ExternalID  string
}

type CreateObjectRetentionPolicyInput struct {
	Name          string
	ObjectPrefix  string
	Mode          string
	RetentionDays int
}

type AuditLogFilter struct {
	SubjectType string
	SubjectID   string
	Since       *time.Time
	Limit       int
}

func (l *Ledger) VerifyCosignSignature(ctx context.Context, actor domain.Actor, in VerifyCosignInput) (domain.CosignVerification, error) {
	if err := ctx.Err(); err != nil {
		return domain.CosignVerification{}, err
	}
	if err := require(actor, ScopeVerifyRead); err != nil {
		return domain.CosignVerification{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sig, ok := l.artifactSigs[strings.TrimSpace(in.ArtifactSignatureID)]
	if !ok || sig.TenantID != actor.TenantID {
		return domain.CosignVerification{}, ErrNotFound
	}
	artifact, artifactOK := l.artifacts[sig.ArtifactID]
	if !artifactOK || artifact.TenantID != actor.TenantID {
		return domain.CosignVerification{}, ErrNotFound
	}
	checks := []domain.VerifyCheck{}
	result := "passed"
	if artifact.Digest != sig.SubjectDigest || !validDigest(sig.SubjectDigest) {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "subject_digest", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "subject_digest", Result: "passed"})
	}
	if strings.TrimSpace(sig.Signature) == "" {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "signature_present", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "signature_present", Result: "passed"})
	}
	if strings.TrimSpace(in.RekorUUID) != "" || strings.TrimSpace(in.RekorLogIndex) != "" {
		checks = append(checks, domain.VerifyCheck{Name: "rekor_metadata", Result: "passed", Detail: "metadata captured; online transparency verification is not implied"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "rekor_metadata", Result: "skipped", Detail: "no Rekor metadata supplied"})
	}
	var imageID string
	for _, image := range l.images {
		if image.TenantID == actor.TenantID && image.ArtifactID == artifact.ID && image.Digest == artifact.Digest {
			imageID = image.ID
			break
		}
	}
	record := domain.CosignVerification{
		ID:                  newID("cosv"),
		TenantID:            actor.TenantID,
		ArtifactID:          artifact.ID,
		ContainerImageID:    imageID,
		ArtifactSignatureID: sig.ID,
		SubjectDigest:       sig.SubjectDigest,
		RekorUUID:           strings.TrimSpace(in.RekorUUID),
		RekorLogIndex:       strings.TrimSpace(in.RekorLogIndex),
		CertificateIdentity: strings.TrimSpace(in.CertificateIdentity),
		CertificateIssuer:   strings.TrimSpace(in.CertificateIssuer),
		Result:              result,
		Checks:              checks,
		SchemaVersion:       domain.CosignVerificationSchemaVersion,
		CreatedAt:           l.now(),
	}
	l.cosignVerifs[record.ID] = record
	l.verifications[record.ID] = domain.VerificationResult{ID: record.ID, TenantID: actor.TenantID, SubjectType: "artifact_signature", SubjectID: sig.ID, Result: result, Checks: checks, VerifiedAt: record.CreatedAt}
	_, _ = l.appendChainLocked(actor.TenantID, "cosign_signature.verified", "artifact_signature", sig.ID, actorType(actor), actorID(actor), sig.SubjectDigest, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CosignVerification{}, err
	}
	if result != "passed" {
		return record, ErrVerificationFailed
	}
	return record, nil
}

func (l *Ledger) RevokeSigningKey(ctx context.Context, actor domain.Actor, keyID, reason string) (domain.SigningKey, error) {
	if err := ctx.Err(); err != nil {
		return domain.SigningKey{}, err
	}
	if err := require(actor, ScopeKeysAdmin); err != nil {
		return domain.SigningKey{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, ok := l.signingKeys[strings.TrimSpace(keyID)]
	if !ok || key.TenantID != actor.TenantID {
		return domain.SigningKey{}, ErrNotFound
	}
	if key.Status == "revoked" {
		return domain.SigningKey{}, ErrConflict
	}
	now := l.now()
	key.Status = "revoked"
	key.RevokedAt = &now
	l.signingKeys[key.ID] = key
	_, _ = l.appendChainLocked(actor.TenantID, "signing_key.revoked", "signing_key", key.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SigningKey{}, err
	}
	key.Private = nil
	_ = reason
	return key, nil
}

func (l *Ledger) CreateSigningProvider(ctx context.Context, actor domain.Actor, in CreateSigningProviderInput) (domain.SigningProvider, error) {
	if err := ctx.Err(); err != nil {
		return domain.SigningProvider{}, err
	}
	if err := require(actor, ScopeKeysAdmin); err != nil {
		return domain.SigningProvider{}, err
	}
	in.Name, in.Type, in.KeyRef = strings.TrimSpace(in.Name), strings.TrimSpace(in.Type), strings.TrimSpace(in.KeyRef)
	if in.Name == "" || in.KeyRef == "" || !validSigningProviderType(in.Type) {
		return domain.SigningProvider{}, ErrValidation
	}
	if in.Type == "local_encrypted_dev" && !in.Encrypted {
		return domain.SigningProvider{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	provider := domain.SigningProvider{ID: newID("sp"), TenantID: actor.TenantID, Name: in.Name, Type: in.Type, Status: "active", KeyRef: in.KeyRef, Encrypted: in.Encrypted, SchemaVersion: domain.SigningProviderSchemaVersion, CreatedAt: l.now()}
	l.signingProviders[provider.ID] = provider
	_, _ = l.appendChainLocked(actor.TenantID, "signing_provider.created", "signing_provider", provider.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SigningProvider{}, err
	}
	return provider, nil
}

func (l *Ledger) CreateMerkleBatch(ctx context.Context, actor domain.Actor, in CreateMerkleBatchInput) (domain.MerkleBatch, error) {
	if err := ctx.Err(); err != nil {
		return domain.MerkleBatch{}, err
	}
	if err := require(actor, ScopeKeysAdmin); err != nil {
		return domain.MerkleBatch{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := l.chain[actor.TenantID]
	if len(entries) == 0 {
		return domain.MerkleBatch{}, ErrValidation
	}
	from, to := in.FromSequence, in.ToSequence
	if from == 0 {
		from = 1
	}
	if to == 0 {
		to = int64(len(entries))
	}
	if from < 1 || to < from || to > int64(len(entries)) {
		return domain.MerkleBatch{}, ErrValidation
	}
	leaves := []string{}
	for _, entry := range entries {
		if entry.Sequence >= from && entry.Sequence <= to {
			leaves = append(leaves, entry.EntryHash)
		}
	}
	root := merkleRoot(leaves)
	sig, err := l.signLocked(actor.TenantID, "merkle_batch", "pending", []byte(root))
	if err != nil {
		return domain.MerkleBatch{}, err
	}
	batch := domain.MerkleBatch{ID: newID("mb"), TenantID: actor.TenantID, FromSequence: from, ToSequence: to, EntryCount: len(leaves), LeafHashes: leaves, RootHash: root, SignatureRefs: []string{sig.ID}, SchemaVersion: domain.MerkleBatchSchemaVersion, CreatedAt: l.now()}
	l.merkleBatches[batch.ID] = batch
	_, _ = l.appendChainLocked(actor.TenantID, "merkle_batch.created", "merkle_batch", batch.ID, actorType(actor), actorID(actor), root, sig.ID)
	if err := l.persistLocked(ctx); err != nil {
		return domain.MerkleBatch{}, err
	}
	return batch, nil
}

func (l *Ledger) VerifyMerkleBatch(ctx context.Context, actor domain.Actor, id string) (domain.VerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.VerificationResult{}, err
	}
	if err := require(actor, ScopeVerifyRead); err != nil {
		return domain.VerificationResult{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	batch, ok := l.merkleBatches[strings.TrimSpace(id)]
	if !ok || batch.TenantID != actor.TenantID {
		return domain.VerificationResult{}, ErrNotFound
	}
	result := "passed"
	checks := []domain.VerifyCheck{}
	if got := merkleRoot(batch.LeafHashes); got != batch.RootHash {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "merkle_root", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "merkle_root", Result: "passed"})
	}
	if !l.verifySignatureLocked(actor.TenantID, batch.SignatureRefs, []byte(batch.RootHash)) {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_signature", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "checkpoint_signature", Result: "passed"})
	}
	vr := domain.VerificationResult{ID: newID("vr"), TenantID: actor.TenantID, SubjectType: "merkle_batch", SubjectID: batch.ID, Result: result, Checks: checks, VerifiedAt: l.now()}
	l.verifications[vr.ID] = vr
	if err := l.persistLocked(ctx); err != nil {
		return domain.VerificationResult{}, err
	}
	if result != "passed" {
		return vr, ErrVerificationFailed
	}
	return vr, nil
}

func (l *Ledger) CreateTransparencyCheckpoint(ctx context.Context, actor domain.Actor, in CreateTransparencyCheckpointInput) (domain.TransparencyCheckpoint, error) {
	if err := ctx.Err(); err != nil {
		return domain.TransparencyCheckpoint{}, err
	}
	if err := require(actor, ScopeKeysAdmin); err != nil {
		return domain.TransparencyCheckpoint{}, err
	}
	in.BatchID, in.Provider = strings.TrimSpace(in.BatchID), strings.TrimSpace(in.Provider)
	in.ExternalURL, in.ExternalID = strings.TrimSpace(in.ExternalURL), strings.TrimSpace(in.ExternalID)
	if in.BatchID == "" || in.Provider == "" || (in.ExternalURL == "" && in.ExternalID == "") {
		return domain.TransparencyCheckpoint{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	batch, ok := l.merkleBatches[in.BatchID]
	if !ok || batch.TenantID != actor.TenantID {
		return domain.TransparencyCheckpoint{}, ErrNotFound
	}
	timestampHash, err := canonicalAnyHash(map[string]any{"batch_id": batch.ID, "root_hash": batch.RootHash, "provider": in.Provider, "external_url": in.ExternalURL, "external_id": in.ExternalID})
	if err != nil {
		return domain.TransparencyCheckpoint{}, err
	}
	checkpoint := domain.TransparencyCheckpoint{ID: newID("tcp"), TenantID: actor.TenantID, BatchID: batch.ID, Provider: in.Provider, ExternalURL: in.ExternalURL, ExternalID: in.ExternalID, TimestampHash: timestampHash, State: "recorded", SchemaVersion: domain.TransparencyCheckpointVersion, CreatedAt: l.now()}
	l.transparency[checkpoint.ID] = checkpoint
	_, _ = l.appendChainLocked(actor.TenantID, "transparency_checkpoint.recorded", "transparency_checkpoint", checkpoint.ID, actorType(actor), actorID(actor), timestampHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.TransparencyCheckpoint{}, err
	}
	return checkpoint, nil
}

func (l *Ledger) CreateObjectRetentionPolicy(ctx context.Context, actor domain.Actor, in CreateObjectRetentionPolicyInput) (domain.ObjectRetentionPolicy, error) {
	if err := ctx.Err(); err != nil {
		return domain.ObjectRetentionPolicy{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.ObjectRetentionPolicy{}, err
	}
	in.Name, in.ObjectPrefix, in.Mode = strings.TrimSpace(in.Name), strings.TrimSpace(in.ObjectPrefix), strings.TrimSpace(in.Mode)
	if in.Name == "" || in.RetentionDays <= 0 || (in.Mode != "governance" && in.Mode != "compliance") {
		return domain.ObjectRetentionPolicy{}, ErrValidation
	}
	if in.ObjectPrefix == "" {
		in.ObjectPrefix = "tenants/" + actor.TenantID + "/"
	}
	expectedPrefix := "tenants/" + actor.TenantID + "/"
	if !strings.HasPrefix(in.ObjectPrefix, expectedPrefix) {
		return domain.ObjectRetentionPolicy{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	policy := domain.ObjectRetentionPolicy{ID: newID("orp"), TenantID: actor.TenantID, Name: in.Name, ObjectPrefix: in.ObjectPrefix, Mode: in.Mode, RetentionDays: in.RetentionDays, Status: "configured", SchemaVersion: domain.ObjectRetentionPolicyVersion, CreatedAt: l.now()}
	l.retentionPolicies[policy.ID] = policy
	_, _ = l.appendChainLocked(actor.TenantID, "object_retention_policy.created", "object_retention_policy", policy.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ObjectRetentionPolicy{}, err
	}
	return policy, nil
}

func (l *Ledger) VerifyObjectRetentionPolicy(ctx context.Context, actor domain.Actor, id string) (domain.ObjectRetentionPolicy, error) {
	if err := ctx.Err(); err != nil {
		return domain.ObjectRetentionPolicy{}, err
	}
	if err := require(actor, ScopeVerifyRead); err != nil {
		return domain.ObjectRetentionPolicy{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	policy, ok := l.retentionPolicies[strings.TrimSpace(id)]
	if !ok || policy.TenantID != actor.TenantID {
		return domain.ObjectRetentionPolicy{}, ErrNotFound
	}
	now := l.now()
	policy.Status = "verified"
	policy.VerifiedAt = &now
	verificationHash, err := canonicalAnyHash(struct {
		ID            string `json:"id"`
		TenantID      string `json:"tenant_id"`
		ObjectPrefix  string `json:"object_prefix"`
		Mode          string `json:"mode"`
		RetentionDays int    `json:"retention_days"`
		Status        string `json:"status"`
		VerifiedAt    string `json:"verified_at"`
	}{
		ID:            policy.ID,
		TenantID:      policy.TenantID,
		ObjectPrefix:  policy.ObjectPrefix,
		Mode:          policy.Mode,
		RetentionDays: policy.RetentionDays,
		Status:        policy.Status,
		VerifiedAt:    now.Format(time.RFC3339Nano),
	})
	if err != nil {
		return domain.ObjectRetentionPolicy{}, err
	}
	policy.VerificationHash = verificationHash
	l.retentionPolicies[policy.ID] = policy
	_, _ = l.appendChainLocked(actor.TenantID, "object_retention_policy.verified", "object_retention_policy", policy.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ObjectRetentionPolicy{}, err
	}
	return policy, nil
}

func (l *Ledger) GenerateBackupManifest(ctx context.Context, actor domain.Actor) (domain.BackupManifest, error) {
	if err := ctx.Err(); err != nil {
		return domain.BackupManifest{}, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return domain.BackupManifest{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.snapshotLocked()
	state.SigningKeyPrivate = nil
	hash, err := canonicalAnyHash(state)
	if err != nil {
		return domain.BackupManifest{}, err
	}
	checks := l.verifyChainLocked(actor.TenantID)
	manifest := domain.BackupManifest{
		ID:                newID("bak"),
		TenantID:          actor.TenantID,
		StateHash:         hash,
		ResourceCounts:    l.resourceCountsLocked(actor.TenantID),
		ConsistencyChecks: checks,
		Limitations:       []string{"Backup manifests intentionally exclude raw private keys and raw payload bytes; restore requires database and object-store backups from the same point in time."},
		SchemaVersion:     domain.BackupManifestSchemaVersion,
		CreatedAt:         l.now(),
	}
	l.backupManifests[manifest.ID] = manifest
	_, _ = l.appendChainLocked(actor.TenantID, "backup_manifest.generated", "backup_manifest", manifest.ID, actorType(actor), actorID(actor), hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.BackupManifest{}, err
	}
	return manifest, nil
}

func (l *Ledger) VerifyBackupManifest(ctx context.Context, actor domain.Actor, id string) (domain.VerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.VerificationResult{}, err
	}
	if err := require(actor, ScopeVerifyRead); err != nil {
		return domain.VerificationResult{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	manifest, ok := l.backupManifests[strings.TrimSpace(id)]
	if !ok || manifest.TenantID != actor.TenantID {
		return domain.VerificationResult{}, ErrNotFound
	}
	result := "passed"
	checks := append([]domain.VerifyCheck(nil), manifest.ConsistencyChecks...)
	for _, check := range checks {
		if check.Result == "failed" {
			result = "failed"
			break
		}
	}
	checks = append(checks, domain.VerifyCheck{Name: "backup_manifest_present", Result: "passed", Detail: manifest.StateHash})
	vr := domain.VerificationResult{ID: newID("vr"), TenantID: actor.TenantID, SubjectType: "backup_manifest", SubjectID: manifest.ID, Result: result, Checks: checks, VerifiedAt: l.now()}
	l.verifications[vr.ID] = vr
	if err := l.persistLocked(ctx); err != nil {
		return domain.VerificationResult{}, err
	}
	if result != "passed" {
		return vr, ErrVerificationFailed
	}
	return vr, nil
}

func (l *Ledger) ReadinessStatus(ctx context.Context) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	checks := []map[string]string{{"name": "ledger", "status": "ok"}}
	if l.store == nil {
		checks = append(checks, map[string]string{"name": "store", "status": "memory"})
	} else {
		checks = append(checks, map[string]string{"name": "store", "status": "configured"})
	}
	if l.objects == nil {
		checks = append(checks, map[string]string{"name": "object_store", "status": "not_configured"})
	} else {
		checks = append(checks, map[string]string{"name": "object_store", "status": "configured"})
	}
	return map[string]any{"status": "ok", "checks": checks}, nil
}

func (l *Ledger) Metrics(ctx context.Context, actor domain.Actor) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	portalFailures := 0
	portalRevoked := 0
	for _, access := range l.portalAccess {
		if access.TenantID == actor.TenantID {
			portalFailures += access.FailedAccessCount
			if access.RevokedAt != nil {
				portalRevoked++
			}
		}
	}
	return map[string]any{"tenant_id": actor.TenantID, "resource_counts": l.resourceCountsLocked(actor.TenantID), "customer_portal_failed_access_count": portalFailures, "customer_portal_revoked_access_count": portalRevoked}, nil
}

func (l *Ledger) ListAuditLog(ctx context.Context, actor domain.Actor, filter AuditLogFilter) ([]domain.AuditChainEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeAdmin); err != nil {
		return nil, err
	}
	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 100
	}
	subjectType, subjectID := strings.TrimSpace(filter.SubjectType), strings.TrimSpace(filter.SubjectID)
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := l.chain[actor.TenantID]
	out := []domain.AuditChainEntry{}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if subjectType != "" && entry.SubjectType != subjectType {
			continue
		}
		if subjectID != "" && entry.SubjectID != subjectID {
			continue
		}
		if filter.Since != nil && entry.OccurredAt.Before(filter.Since.UTC()) {
			continue
		}
		out = append(out, entry)
		if len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
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

func merkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return ""
	}
	level := append([]string(nil), leaves...)
	for len(level) > 1 {
		next := []string{}
		for i := 0; i < len(level); i += 2 {
			right := level[i]
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, hashBytes([]byte(level[i]+"\n"+right)))
		}
		level = next
	}
	return level[0]
}

func validSigningProviderType(value string) bool {
	switch value {
	case "local_encrypted_dev", "aws_kms", "gcp_kms", "azure_key_vault", "pkcs11_hsm":
		return true
	default:
		return false
	}
}
