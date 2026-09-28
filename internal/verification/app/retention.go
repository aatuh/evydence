package app

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	defaultRetentionVerificationAgeHours = 24
	maxRetentionVerificationAgeHours     = 24 * 366
)

type CreateObjectRetentionPolicyInput struct {
	Name                    string
	ObjectPrefix            string
	ObjectKey               string
	Mode                    string
	RetentionDays           int
	MaxVerificationAgeHours int
	RequireLegalHold        bool
}

type RetentionRequest struct {
	TenantID         string
	ObjectPrefix     string
	ObjectKey        string
	Mode             string
	RetentionDays    int
	RequireLegalHold bool
}

type RetentionObservation struct {
	Provider      string
	Bucket        string
	ObjectKey     string
	Mode          string
	RetentionDays int
	Enforced      bool
	LegalHold     *bool
	ObservedAt    time.Time
	Checks        []verificationdomain.VerifyCheck
	Limitations   []string
}

type SigningCustodySnapshot struct {
	TenantID                string
	SigningProviders        []verificationdomain.SigningProvider
	ObjectRetentionPolicies []verificationdomain.ObjectRetentionPolicy
}

type BackupSnapshot struct {
	TenantID          string
	StateHash         string
	ResourceCounts    map[string]int
	ConsistencyChecks []verificationdomain.VerifyCheck
}

func (s *Service) CreateObjectRetentionPolicy(ctx context.Context, actor identitydomain.Actor, input CreateObjectRetentionPolicyInput) (verificationdomain.ObjectRetentionPolicy, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	if err := s.authorize(ctx, actor, ScopeAdmin, application.ResourceReferences{}, false, true); err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	input.Name = strings.TrimSpace(input.Name)
	input.ObjectPrefix = strings.TrimSpace(input.ObjectPrefix)
	input.ObjectKey = strings.TrimSpace(input.ObjectKey)
	input.Mode = strings.TrimSpace(input.Mode)
	if input.MaxVerificationAgeHours == 0 {
		input.MaxVerificationAgeHours = defaultRetentionVerificationAgeHours
	}
	if input.ObjectPrefix == "" {
		input.ObjectPrefix = "tenants/" + actor.TenantID + "/"
	}
	if !validObjectRetentionPolicyInput(actor.TenantID, input) {
		return verificationdomain.ObjectRetentionPolicy{}, ErrValidation
	}
	now := s.clock.Now().UTC()
	policy := verificationdomain.ObjectRetentionPolicy{
		ID: s.ids.NewID("orp"), TenantID: actor.TenantID, Name: input.Name, ObjectPrefix: input.ObjectPrefix,
		ObjectKey: input.ObjectKey, RequireLegalHold: input.RequireLegalHold, Mode: input.Mode, RetentionDays: input.RetentionDays,
		MaxVerificationAgeHours: input.MaxVerificationAgeHours, Status: "configured",
		SchemaVersion: verificationdomain.ObjectRetentionPolicyVersion, CreatedAt: now,
	}
	err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeAdmin, TenantWide: true}); err != nil {
			return err
		}
		if err := tx.Verification().InsertObjectRetentionPolicy(ctx, policy); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "object_retention_policy.created", "object_retention_policy", policy.ID))
		return err
	})
	if err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	return cloneObjectRetentionPolicy(policy), nil
}

func (s *Service) VerifyObjectRetentionPolicy(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	if err := s.authorize(ctx, actor, ScopeVerifyRead, application.ResourceReferences{}, false, true); err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	id = strings.TrimSpace(id)
	policy, err := s.integrity.ReadObjectRetentionPolicy(ctx, actor.TenantID, id)
	if err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	if policy.ID != id || policy.TenantID != actor.TenantID {
		return verificationdomain.ObjectRetentionPolicy{}, ErrNotFound
	}
	if policy.MaxVerificationAgeHours == 0 {
		policy.MaxVerificationAgeHours = defaultRetentionVerificationAgeHours
	}
	expectedStatus := policy.Status
	now := s.clock.Now().UTC()
	observation, configured, observationErr := s.retentionVerifier.VerifyRetention(ctx, RetentionRequest{
		TenantID: policy.TenantID, ObjectPrefix: policy.ObjectPrefix, ObjectKey: policy.ObjectKey, Mode: policy.Mode,
		RetentionDays: policy.RetentionDays, RequireLegalHold: policy.RequireLegalHold,
	})
	if errors.Is(observationErr, context.Canceled) || errors.Is(observationErr, context.DeadlineExceeded) {
		return verificationdomain.ObjectRetentionPolicy{}, observationErr
	}
	observation = cloneRetentionObservation(observation)
	result := localRetentionIntentResult()
	status := "not_verified"
	providerObserved := false
	if configured {
		if observationErr != nil {
			result = unavailableRetentionResult()
		} else {
			if observation.ObservedAt.IsZero() {
				observation.ObservedAt = now
			}
			result = providerRetentionResult(policy, observation)
			status = retentionVerificationStatus(policy, observation)
			providerObserved = true
		}
	}
	policy.Status = status
	policy.VerifiedAt = timePointer(now)
	policy.VerificationChecks = append([]verificationdomain.VerifyCheck(nil), result.Checks...)
	policy.VerificationLimitations = append([]string(nil), result.Limitations...)
	clearRetentionObservation(&policy)
	if providerObserved {
		policy.VerificationProvider = strings.TrimSpace(result.Provider)
		policy.VerificationBucket = strings.TrimSpace(result.Bucket)
		policy.VerificationMode = strings.TrimSpace(result.Mode)
		policy.VerificationRetentionDays = result.RetentionDays
		policy.VerificationLegalHold = boolPointerValue(result.LegalHold)
		observedAt := result.ObservedAt.UTC()
		policy.VerificationObservedAt = &observedAt
		if policy.Status == "verified" {
			expiresAt := observedAt.Add(time.Duration(policy.MaxVerificationAgeHours) * time.Hour)
			policy.VerificationExpiresAt = &expiresAt
		}
	}
	verificationHash, err := s.canonicalHasher.Hash(retentionVerificationCanonicalValue(policy, now))
	if err != nil || strings.TrimSpace(verificationHash) == "" {
		if err != nil {
			return verificationdomain.ObjectRetentionPolicy{}, err
		}
		return verificationdomain.ObjectRetentionPolicy{}, ErrValidation
	}
	policy.VerificationHash = verificationHash
	entryType := "object_retention_policy.verified"
	if policy.Status != "verified" {
		entryType = "object_retention_policy.verification_failed"
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, TenantWide: true}); err != nil {
			return err
		}
		current, err := tx.Verification().GetObjectRetentionPolicyForUpdate(ctx, actor.TenantID, policy.ID)
		if err != nil {
			return err
		}
		if current.ID != policy.ID || current.TenantID != actor.TenantID {
			return ErrNotFound
		}
		if current.Status != expectedStatus {
			return ErrConflict
		}
		if err := tx.Verification().UpdateObjectRetentionPolicy(ctx, policy, expectedStatus); err != nil {
			return err
		}
		audit := s.auditEvent(actor, now, entryType, "object_retention_policy", policy.ID)
		audit.PayloadHash = policy.VerificationHash
		_, err = tx.Audit().AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	return cloneObjectRetentionPolicy(policy), nil
}

func (s *Service) SigningCustodyReviewReport(ctx context.Context, actor identitydomain.Actor) (verificationdomain.SigningCustodyReviewReport, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.SigningCustodyReviewReport{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.SigningCustodyReviewReport{}, err
	}
	if err := s.authorize(ctx, actor, ScopeKeysAdmin, application.ResourceReferences{}, false, true); err != nil {
		return verificationdomain.SigningCustodyReviewReport{}, err
	}
	snapshot, err := s.integrity.ReadSigningCustodySnapshot(ctx, actor.TenantID)
	if err != nil {
		return verificationdomain.SigningCustodyReviewReport{}, err
	}
	if snapshot.TenantID != actor.TenantID {
		return verificationdomain.SigningCustodyReviewReport{}, ErrNotFound
	}
	providers := append([]verificationdomain.SigningProvider(nil), snapshot.SigningProviders...)
	policies := make([]verificationdomain.ObjectRetentionPolicy, 0, len(snapshot.ObjectRetentionPolicies))
	hasProductionProvider, hasNativePKCS11, hasVerifiedRetention := false, false, false
	for _, provider := range providers {
		if provider.TenantID != actor.TenantID {
			return verificationdomain.SigningCustodyReviewReport{}, ErrNotFound
		}
		if provider.Type != "local_encrypted_dev" {
			hasProductionProvider = true
		}
		if provider.Type == "native_pkcs11_hsm" {
			hasNativePKCS11 = true
		}
	}
	for _, policy := range snapshot.ObjectRetentionPolicies {
		if policy.TenantID != actor.TenantID {
			return verificationdomain.SigningCustodyReviewReport{}, ErrNotFound
		}
		current := currentRetentionPolicy(policy, s.clock.Now().UTC())
		policies = append(policies, current)
		if current.Status == "verified" && current.VerificationHash != "" {
			hasVerifiedRetention = true
		}
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].ID < providers[j].ID })
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	return verificationdomain.SigningCustodyReviewReport{
		ReportType: "signing_custody_review", TenantID: actor.TenantID, SigningProviders: providers, ObjectRetentionPolicies: policies,
		Checks: []verificationdomain.VerifyCheck{
			{Name: "production_signing_provider_recorded", Result: checkResultString(hasProductionProvider), Detail: "At least one non-local signing provider is recorded for the tenant."},
			{Name: "native_pkcs11_hsm_profile_recorded", Result: checkResultString(hasNativePKCS11), Detail: "A native PKCS#11/HSM custody profile is recorded when the deployment uses local HSM modules or slots."},
			{Name: "object_lock_proof_recorded", Result: checkResultString(hasVerifiedRetention), Detail: "At least one object-retention policy has provider verification hash material."},
		},
		Assumptions: []string{
			"Custody review uses Evydence records and configured provider verification receipts.",
			"Native PKCS#11/HSM records describe operator-supplied module and key references; Evydence does not load HSM modules in this API process.",
		},
		Limitations: []string{
			"This report does not prove legal compliance, certification, HSM hardware custody, WORM enforcement, or deployment security.",
			"Operators remain responsible for HSM driver installation, slot access controls, IAM policy, object-store retention settings, and independent review.",
		},
		GeneratedAt: s.clock.Now().UTC(),
	}, nil
}

func (s *Service) GenerateBackupManifest(ctx context.Context, actor identitydomain.Actor) (verificationdomain.BackupManifest, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.BackupManifest{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.BackupManifest{}, err
	}
	if err := s.authorize(ctx, actor, ScopeAdmin, application.ResourceReferences{}, false, true); err != nil {
		return verificationdomain.BackupManifest{}, err
	}
	snapshot, err := s.integrity.ReadCommittedBackupSnapshot(ctx, actor.TenantID)
	if err != nil {
		return verificationdomain.BackupManifest{}, err
	}
	if snapshot.TenantID != actor.TenantID || strings.TrimSpace(snapshot.StateHash) == "" {
		return verificationdomain.BackupManifest{}, ErrNotFound
	}
	now := s.clock.Now().UTC()
	manifest := verificationdomain.BackupManifest{
		ID: s.ids.NewID("bak"), TenantID: actor.TenantID, StateHash: snapshot.StateHash,
		ResourceCounts: cloneStringIntMap(snapshot.ResourceCounts), ConsistencyChecks: append([]verificationdomain.VerifyCheck(nil), snapshot.ConsistencyChecks...),
		Limitations:   []string{"Backup manifests intentionally exclude raw private keys and raw payload bytes; restore requires database and object-store backups from the same point in time."},
		SchemaVersion: verificationdomain.BackupManifestSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeAdmin, TenantWide: true}); err != nil {
			return err
		}
		if err := tx.Verification().InsertBackupManifest(ctx, manifest); err != nil {
			return err
		}
		audit := s.auditEvent(actor, now, "backup_manifest.generated", "backup_manifest", manifest.ID)
		audit.PayloadHash = manifest.StateHash
		_, err := tx.Audit().AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return verificationdomain.BackupManifest{}, err
	}
	return cloneBackupManifest(manifest), nil
}

func validObjectRetentionPolicyInput(tenantID string, input CreateObjectRetentionPolicyInput) bool {
	if input.Name == "" || input.RetentionDays <= 0 || (input.Mode != "governance" && input.Mode != "compliance") || input.MaxVerificationAgeHours < 1 || input.MaxVerificationAgeHours > maxRetentionVerificationAgeHours {
		return false
	}
	prefix := "tenants/" + tenantID + "/"
	if !strings.HasPrefix(input.ObjectPrefix, prefix) || (input.ObjectKey != "" && (!strings.HasPrefix(input.ObjectKey, prefix) || !strings.HasPrefix(input.ObjectKey, input.ObjectPrefix))) {
		return false
	}
	return !input.RequireLegalHold || input.ObjectKey != ""
}

func localRetentionIntentResult() RetentionObservation {
	return RetentionObservation{
		Checks: []verificationdomain.VerifyCheck{
			{Name: "retention_policy_recorded", Result: "passed", Detail: "Tenant-scoped retention intent was recorded."},
			{Name: "provider_verifier_configured", Result: "skipped", Detail: "No provider-backed object-lock verifier is configured."},
			{Name: "provider_bucket_configuration", Result: "skipped", Detail: "No provider bucket configuration was observed."},
			{Name: "provider_enforced_proof", Result: "skipped", Detail: "Provider-enforced retention was not verified."},
		},
		Limitations: []string{"Provider-enforced object-lock, bucket versioning, and WORM settings were not checked by this ledger instance."},
	}
}

func unavailableRetentionResult() RetentionObservation {
	return RetentionObservation{
		Checks: []verificationdomain.VerifyCheck{
			{Name: "retention_policy_recorded", Result: "passed", Detail: "Tenant-scoped retention intent was recorded."},
			{Name: "provider_verifier_configured", Result: "passed", Detail: "A provider-backed object-lock verifier is configured."},
			{Name: "provider_observation", Result: "error", Detail: "Provider retention observation did not complete."},
			{Name: "provider_enforced_proof", Result: "error", Detail: "Provider-enforced retention cannot be inferred while observation is unavailable."},
		},
		Limitations: []string{"Provider retention verification was unavailable; do not infer provider enforcement from this policy record."},
	}
}

func providerRetentionResult(policy verificationdomain.ObjectRetentionPolicy, result RetentionObservation) RetentionObservation {
	checks := append([]verificationdomain.VerifyCheck{{Name: "retention_policy_recorded", Result: "passed", Detail: "Tenant-scoped retention intent was recorded."}, {Name: "provider_verifier_configured", Result: "passed", Detail: "A provider-backed object-lock verifier is configured."}}, result.Checks...)
	bucketEvidence := strings.TrimSpace(result.Provider) != "" && strings.TrimSpace(result.Bucket) != ""
	sampleEvidence := policy.ObjectKey == "" || strings.TrimSpace(result.ObjectKey) == policy.ObjectKey
	metadataComplete := retentionProviderMetadataComplete(policy, result)
	checks = append(checks, verificationdomain.VerifyCheck{Name: "provider_bucket_configuration", Result: checkResultString(bucketEvidence), Detail: "Provider, bucket, mode, duration, and observation time must be recorded for a positive provider result."})
	if policy.ObjectKey != "" {
		checks = append(checks, verificationdomain.VerifyCheck{Name: "provider_sample_object", Result: checkResultString(sampleEvidence), Detail: "Provider observation must identify the configured tenant-scoped sample object."})
	}
	proof := result.Enforced && metadataComplete && retentionChecksPassed(result.Checks)
	checks = append(checks, verificationdomain.VerifyCheck{Name: "provider_enforced_proof", Result: checkResultString(proof), Detail: "Provider enforcement requires complete observation metadata and passing provider checks."})
	result.Checks = checks
	result.Limitations = append([]string{"Provider verification reflects an observation at the recorded time and must be refreshed before its configured expiry."}, result.Limitations...)
	return result
}

func retentionVerificationStatus(policy verificationdomain.ObjectRetentionPolicy, result RetentionObservation) string {
	if !result.Enforced {
		return "not_enforced"
	}
	if !retentionProviderMetadataComplete(policy, result) || !retentionChecksPassed(result.Checks) {
		return "not_verified"
	}
	return "verified"
}

func retentionProviderMetadataComplete(policy verificationdomain.ObjectRetentionPolicy, result RetentionObservation) bool {
	if strings.TrimSpace(result.Provider) == "" || strings.TrimSpace(result.Bucket) == "" || result.ObservedAt.IsZero() || !strings.EqualFold(strings.TrimSpace(result.Mode), policy.Mode) || result.RetentionDays < policy.RetentionDays {
		return false
	}
	if policy.ObjectKey != "" && strings.TrimSpace(result.ObjectKey) != policy.ObjectKey {
		return false
	}
	if policy.ObjectKey != "" && result.LegalHold == nil {
		return false
	}
	return !policy.RequireLegalHold || (result.LegalHold != nil && *result.LegalHold)
}

func retentionChecksPassed(checks []verificationdomain.VerifyCheck) bool {
	if len(checks) == 0 {
		return false
	}
	for _, check := range checks {
		if check.Result != "passed" {
			return false
		}
	}
	return true
}

func currentRetentionPolicy(policy verificationdomain.ObjectRetentionPolicy, now time.Time) verificationdomain.ObjectRetentionPolicy {
	policy = cloneObjectRetentionPolicy(policy)
	if policy.Status != "verified" || (policy.VerificationExpiresAt != nil && now.Before(*policy.VerificationExpiresAt)) {
		return policy
	}
	policy.Status = "stale"
	policy.VerificationChecks = append(policy.VerificationChecks, verificationdomain.VerifyCheck{Name: "provider_observation_freshness", Result: "failed", Detail: "Provider retention observation exceeded this policy's maximum verification age."})
	policy.VerificationLimitations = append(policy.VerificationLimitations, "Provider retention observation is stale and must be refreshed before it can be treated as current.")
	return policy
}

func retentionVerificationCanonicalValue(policy verificationdomain.ObjectRetentionPolicy, verifiedAt time.Time) any {
	return struct {
		ID                        string                           `json:"id"`
		TenantID                  string                           `json:"tenant_id"`
		ObjectPrefix              string                           `json:"object_prefix"`
		ObjectKey                 string                           `json:"object_key,omitempty"`
		RequireLegalHold          bool                             `json:"require_legal_hold"`
		Mode                      string                           `json:"mode"`
		RetentionDays             int                              `json:"retention_days"`
		MaxVerificationAgeHours   int                              `json:"max_verification_age_hours"`
		Status                    string                           `json:"status"`
		VerifiedAt                string                           `json:"verified_at"`
		VerificationProvider      string                           `json:"verification_provider,omitempty"`
		VerificationBucket        string                           `json:"verification_bucket,omitempty"`
		VerificationMode          string                           `json:"verification_mode,omitempty"`
		VerificationRetentionDays int                              `json:"verification_retention_days,omitempty"`
		VerificationLegalHold     *bool                            `json:"verification_legal_hold,omitempty"`
		VerificationObservedAt    string                           `json:"verification_observed_at,omitempty"`
		VerificationExpiresAt     string                           `json:"verification_expires_at,omitempty"`
		Checks                    []verificationdomain.VerifyCheck `json:"checks"`
		Limitations               []string                         `json:"limitations"`
	}{
		ID: policy.ID, TenantID: policy.TenantID, ObjectPrefix: policy.ObjectPrefix, ObjectKey: policy.ObjectKey,
		RequireLegalHold: policy.RequireLegalHold, Mode: policy.Mode, RetentionDays: policy.RetentionDays,
		MaxVerificationAgeHours: policy.MaxVerificationAgeHours, Status: policy.Status, VerifiedAt: verifiedAt.Format(time.RFC3339Nano),
		VerificationProvider: policy.VerificationProvider, VerificationBucket: policy.VerificationBucket,
		VerificationMode: policy.VerificationMode, VerificationRetentionDays: policy.VerificationRetentionDays,
		VerificationLegalHold: boolPointerValue(policy.VerificationLegalHold), VerificationObservedAt: timeString(policy.VerificationObservedAt),
		VerificationExpiresAt: timeString(policy.VerificationExpiresAt), Checks: append([]verificationdomain.VerifyCheck(nil), policy.VerificationChecks...),
		Limitations: append([]string(nil), policy.VerificationLimitations...),
	}
}

func clearRetentionObservation(policy *verificationdomain.ObjectRetentionPolicy) {
	policy.VerificationProvider = ""
	policy.VerificationBucket = ""
	policy.VerificationMode = ""
	policy.VerificationRetentionDays = 0
	policy.VerificationLegalHold = nil
	policy.VerificationObservedAt = nil
	policy.VerificationExpiresAt = nil
}

func cloneRetentionObservation(value RetentionObservation) RetentionObservation {
	value.LegalHold = boolPointerValue(value.LegalHold)
	value.Checks = append([]verificationdomain.VerifyCheck(nil), value.Checks...)
	value.Limitations = append([]string(nil), value.Limitations...)
	return value
}

func cloneObjectRetentionPolicy(value verificationdomain.ObjectRetentionPolicy) verificationdomain.ObjectRetentionPolicy {
	value.VerifiedAt = timePointerValue(value.VerifiedAt)
	value.VerificationChecks = append([]verificationdomain.VerifyCheck(nil), value.VerificationChecks...)
	value.VerificationLimitations = append([]string(nil), value.VerificationLimitations...)
	value.VerificationLegalHold = boolPointerValue(value.VerificationLegalHold)
	value.VerificationObservedAt = timePointerValue(value.VerificationObservedAt)
	value.VerificationExpiresAt = timePointerValue(value.VerificationExpiresAt)
	return value
}

func cloneBackupSnapshot(value BackupSnapshot) BackupSnapshot {
	value.ResourceCounts = cloneStringIntMap(value.ResourceCounts)
	value.ConsistencyChecks = append([]verificationdomain.VerifyCheck(nil), value.ConsistencyChecks...)
	return value
}

func cloneBackupManifest(value verificationdomain.BackupManifest) verificationdomain.BackupManifest {
	value.ResourceCounts = cloneStringIntMap(value.ResourceCounts)
	value.ConsistencyChecks = append([]verificationdomain.VerifyCheck(nil), value.ConsistencyChecks...)
	value.Limitations = append([]string(nil), value.Limitations...)
	return value
}

func cloneStringIntMap(value map[string]int) map[string]int {
	if value == nil {
		return nil
	}
	result := make(map[string]int, len(value))
	for key, count := range value {
		result[key] = count
	}
	return result
}

func boolPointerValue(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func timeString(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func checkResultString(ok bool) string {
	if ok {
		return "passed"
	}
	return "failed"
}
