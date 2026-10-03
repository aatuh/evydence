package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type VerifyCosignInput struct {
	ArtifactSignatureID string
	ExpectedIdentity    string
	ExpectedIssuer      string
	Mode                CosignVerificationMode
	Offline             bool
}

type CreateSigningProviderInput struct {
	Name      string
	Type      string
	KeyRef    string
	Encrypted bool
}

type SigningKeyRevocationInput struct {
	Reason                   string
	Semantics                string
	HistoricalValidityPolicy string
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
	Name                    string
	ObjectPrefix            string
	ObjectKey               string
	Mode                    string
	RetentionDays           int
	MaxVerificationAgeHours int
	RequireLegalHold        bool
}

const (
	defaultRetentionVerificationAgeHours = 24
	maxRetentionVerificationAgeHours     = 24 * 366
)

type AuditLogFilter struct {
	SubjectType string
	SubjectID   string
	Since       *time.Time
	Limit       int
}

func cosignVerificationProfile(mode CosignVerificationMode, digest string) domain.VerificationProfile {
	return verificationProfileFromContext(verificationapp.CosignFullProfile(verificationapp.CosignVerificationMode(mode), digest))
}

func loadCosignBundle(ctx context.Context, tenantID string, sig domain.ArtifactSignature, objects ObjectStore, store Store) ([]byte, error) {
	if objects == nil || !validDigest(sig.PayloadHash) {
		return nil, ErrVerificationFailed
	}
	_, expectedKey, err := CanonicalObjectPayloadKeys(tenantID, sig.PayloadHash)
	if err != nil || sig.PayloadRef != "object://"+expectedKey {
		return nil, ErrVerificationFailed
	}
	if lifecycle, ok := store.(ObjectPayloadLifecycleStore); ok {
		if err := RequireFinalizedObjectPayload(ctx, lifecycle, tenantID, sig.PayloadHash, expectedKey); err != nil {
			return nil, err
		}
	}
	object, err := objects.Get(ctx, expectedKey)
	if err != nil || object.Key != expectedKey || object.TenantID != tenantID || object.Digest != sig.PayloadHash || hashBytes(object.Bytes) != sig.PayloadHash {
		return nil, ErrVerificationFailed
	}
	return append([]byte(nil), object.Bytes...), nil
}

func (l *Ledger) RevokeSigningKey(ctx context.Context, actor domain.Actor, keyID, reason string) (domain.SigningKey, error) {
	return l.RevokeSigningKeyWithPolicy(ctx, actor, keyID, SigningKeyRevocationInput{
		Reason:                   reason,
		Semantics:                domain.SigningKeyRevocationOrdinary,
		HistoricalValidityPolicy: domain.SigningKeyHistoricalValidityPreserve,
	})
}

func copyBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func (l *Ledger) ReadinessStatus(ctx context.Context) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	checks := append([]ReadinessCheck(nil), l.readinessChecks...)
	l.mu.Unlock()
	return operationsquery.NewReadiness(checks).Public(ctx)
}

// ReadinessDiagnostics returns safe, dependency-specific diagnostics for an
// instance administrator. It deliberately excludes raw probe errors because
// those can contain credentials, hostnames, filesystem paths, or tenant data.
func (l *Ledger) ReadinessDiagnostics(ctx context.Context, actor domain.Actor) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeInstanceAdmin); err != nil {
		return nil, err
	}
	l.mu.Lock()
	checks := append([]ReadinessCheck(nil), l.readinessChecks...)
	l.mu.Unlock()
	return operationsquery.NewReadiness(checks).Operator(ctx, actor)
}

func normalizedReadinessChecks(checks []ReadinessCheck) []ReadinessCheck {
	return operationsquery.NormalizeReadinessChecks(checks)
}

func (l *Ledger) Metrics(ctx context.Context, actor domain.Actor) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	instanceAdmin := actorHasExactScope(actor, ScopeInstanceAdmin)
	if instanceAdmin {
		if err := require(actor, ScopeInstanceAdmin); err != nil {
			return nil, err
		}
	} else if err := require(actor, ScopeAdmin); err != nil {
		return nil, err
	}
	l.mu.Lock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		l.mu.Unlock()
		return nil, err
	}
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
	metrics := map[string]any{"tenant_id": actor.TenantID, "resource_counts": l.resourceCountsLocked(actor.TenantID), "customer_portal_failed_access_count": portalFailures, "customer_portal_revoked_access_count": portalRevoked}
	operator := l.outboxAdmin
	reconciliationMetrics := l.reconciliationMetrics
	l.mu.Unlock()
	if reconciliationMetrics != nil {
		reconciliation, err := reconciliationMetrics.ObjectReconciliationMetrics(ctx, actor.TenantID)
		if err != nil {
			return nil, err
		}
		metrics["object_reconciliation_runs"] = reconciliation.Runs
		metrics["object_reconciliation_scanned_payloads"] = reconciliation.ScannedPayloads
		metrics["object_reconciliation_missing_final_objects"] = reconciliation.MissingFinalObjects
		metrics["object_reconciliation_missing_staged_objects"] = reconciliation.MissingStagedObjects
		metrics["object_reconciliation_digest_mismatches"] = reconciliation.DigestMismatches
		metrics["object_reconciliation_provider_orphans"] = reconciliation.ProviderOrphans
		metrics["object_reconciliation_quarantined_payloads"] = reconciliation.QuarantinedPayloads
		lastRunAgeSeconds := 0
		if !reconciliation.LastRunAt.IsZero() {
			lastRunAgeSeconds = int(time.Since(reconciliation.LastRunAt).Seconds())
			if lastRunAgeSeconds < 0 {
				lastRunAgeSeconds = 0
			}
		}
		metrics["object_reconciliation_last_run_age_seconds"] = lastRunAgeSeconds
	}
	if !instanceAdmin || operator == nil {
		return metrics, nil
	}
	diagnostics, err := operator.OutboxDiagnostics(ctx)
	if err != nil {
		return nil, err
	}
	metrics["outbox_pending_jobs"] = diagnostics.PendingJobs
	metrics["outbox_running_jobs"] = diagnostics.RunningJobs
	metrics["outbox_terminal_jobs"] = diagnostics.TerminalJobs
	oldestAgeSeconds := 0
	if !diagnostics.OldestPendingCreatedAt.IsZero() {
		oldestAgeSeconds = int(time.Since(diagnostics.OldestPendingCreatedAt).Seconds())
		if oldestAgeSeconds < 0 {
			oldestAgeSeconds = 0
		}
	}
	metrics["outbox_oldest_pending_age_seconds"] = oldestAgeSeconds
	return metrics, nil
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
	if err := l.authorizeResourceLocked(actor, ScopeAdmin, resourceRefs{}); err != nil {
		return nil, err
	}
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return nil, err
	}
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
	case "local_encrypted_dev", "aws_kms", "gcp_kms", "azure_key_vault", "pkcs11_hsm", "native_pkcs11_hsm":
		return true
	default:
		return false
	}
}

func signingProviderRefContainsSecret(value string) bool {
	lowered := strings.ToLower(value)
	for _, marker := range []string{"pin-value=", "pin-source=", "password=", "secret=", "token=" + "secret"} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}
