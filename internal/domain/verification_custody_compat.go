package domain

import verificationdomain "github.com/aatuh/evydence/internal/verification/domain"

// Custody mappers keep the persisted/wire DTO boundary separate from the
// verification-owned models, copying mutable receipt fields in both directions.
func SigningProviderToContextModel(value SigningProvider) verificationdomain.SigningProvider {
	return verificationdomain.SigningProvider(value)
}

func SigningProviderFromContextModel(value verificationdomain.SigningProvider) SigningProvider {
	return SigningProvider(value)
}

func cloneCustodyBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func ObjectRetentionPolicyToContextModel(value ObjectRetentionPolicy) verificationdomain.ObjectRetentionPolicy {
	checks := make([]verificationdomain.VerifyCheck, 0, len(value.VerificationChecks))
	for _, check := range value.VerificationChecks {
		checks = append(checks, verificationdomain.VerifyCheck(check))
	}
	return verificationdomain.ObjectRetentionPolicy{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, ObjectPrefix: value.ObjectPrefix, ObjectKey: value.ObjectKey, RequireLegalHold: value.RequireLegalHold, Mode: value.Mode,
		RetentionDays: value.RetentionDays, MaxVerificationAgeHours: value.MaxVerificationAgeHours, Status: value.Status, VerifiedAt: cloneTimePointer(value.VerifiedAt), VerificationHash: value.VerificationHash,
		VerificationChecks: checks, VerificationLimitations: append([]string(nil), value.VerificationLimitations...), VerificationProvider: value.VerificationProvider, VerificationBucket: value.VerificationBucket,
		VerificationMode: value.VerificationMode, VerificationRetentionDays: value.VerificationRetentionDays, VerificationLegalHold: cloneCustodyBool(value.VerificationLegalHold),
		VerificationObservedAt: cloneTimePointer(value.VerificationObservedAt), VerificationExpiresAt: cloneTimePointer(value.VerificationExpiresAt), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func ObjectRetentionPolicyFromContextModel(value verificationdomain.ObjectRetentionPolicy) ObjectRetentionPolicy {
	checks := make([]VerifyCheck, 0, len(value.VerificationChecks))
	for _, check := range value.VerificationChecks {
		checks = append(checks, VerifyCheck(check))
	}
	return ObjectRetentionPolicy{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, ObjectPrefix: value.ObjectPrefix, ObjectKey: value.ObjectKey, RequireLegalHold: value.RequireLegalHold, Mode: value.Mode,
		RetentionDays: value.RetentionDays, MaxVerificationAgeHours: value.MaxVerificationAgeHours, Status: value.Status, VerifiedAt: cloneTimePointer(value.VerifiedAt), VerificationHash: value.VerificationHash,
		VerificationChecks: checks, VerificationLimitations: append([]string(nil), value.VerificationLimitations...), VerificationProvider: value.VerificationProvider, VerificationBucket: value.VerificationBucket,
		VerificationMode: value.VerificationMode, VerificationRetentionDays: value.VerificationRetentionDays, VerificationLegalHold: cloneCustodyBool(value.VerificationLegalHold),
		VerificationObservedAt: cloneTimePointer(value.VerificationObservedAt), VerificationExpiresAt: cloneTimePointer(value.VerificationExpiresAt), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func SigningCustodyReviewFromContextModel(value verificationdomain.SigningCustodyReviewReport) SigningCustodyReviewReport {
	providers := make([]SigningProvider, 0, len(value.SigningProviders))
	for _, provider := range value.SigningProviders {
		providers = append(providers, SigningProviderFromContextModel(provider))
	}
	policies := make([]ObjectRetentionPolicy, 0, len(value.ObjectRetentionPolicies))
	for _, policy := range value.ObjectRetentionPolicies {
		policies = append(policies, ObjectRetentionPolicyFromContextModel(policy))
	}
	checks := make([]VerifyCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, VerifyCheck(check))
	}
	return SigningCustodyReviewReport{ReportType: value.ReportType, TenantID: value.TenantID, SigningProviders: providers, ObjectRetentionPolicies: policies, Checks: checks, Assumptions: append([]string(nil), value.Assumptions...), Limitations: append([]string(nil), value.Limitations...), GeneratedAt: value.GeneratedAt}
}
