package domain

import (
	"reflect"
	"testing"
	"time"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestCustodyCompatibilityMappersPreserveFieldsAndCopyMutableValues(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	hold := true
	provider := SigningProvider{ID: "provider", TenantID: "tenant", Name: "HSM", Type: "native_pkcs11_hsm", Status: "configured", KeyRef: "pkcs11:object=key", Encrypted: true, SchemaVersion: "provider.v1", CreatedAt: now}
	if got := SigningProviderFromContextModel(SigningProviderToContextModel(provider)); !reflect.DeepEqual(got, provider) {
		t.Fatalf("provider changed %#v", got)
	}
	policy := ObjectRetentionPolicy{ID: "policy", TenantID: "tenant", Name: "Retention", ObjectPrefix: "tenants/tenant/", ObjectKey: "tenants/tenant/raw/sample", RequireLegalHold: true, Mode: "compliance", RetentionDays: 30, MaxVerificationAgeHours: 24, Status: "verified", VerifiedAt: &now, VerificationHash: "hash", VerificationChecks: []VerifyCheck{{Name: "check", Result: "passed", Detail: "detail"}}, VerificationLimitations: []string{"limitation"}, VerificationProvider: "s3", VerificationBucket: "bucket", VerificationMode: "compliance", VerificationRetentionDays: 30, VerificationLegalHold: &hold, VerificationObservedAt: &now, VerificationExpiresAt: &now, SchemaVersion: "policy.v2", CreatedAt: now}
	owned := ObjectRetentionPolicyToContextModel(policy)
	if got := ObjectRetentionPolicyFromContextModel(owned); !reflect.DeepEqual(got, policy) {
		t.Fatalf("policy changed %#v", got)
	}
	owned.VerificationChecks[0].Detail = "changed"
	owned.VerificationLimitations[0] = "changed"
	*owned.VerificationLegalHold = false
	*owned.VerifiedAt = now.Add(time.Hour)
	if policy.VerificationChecks[0].Detail != "detail" || policy.VerificationLimitations[0] != "limitation" || !*policy.VerificationLegalHold || !policy.VerifiedAt.Equal(now) {
		t.Fatal("owned policy shares mutable values")
	}
	report := verificationdomain.SigningCustodyReviewReport{ReportType: "signing_custody_review", TenantID: "tenant", SigningProviders: []verificationdomain.SigningProvider{SigningProviderToContextModel(provider)}, ObjectRetentionPolicies: []verificationdomain.ObjectRetentionPolicy{ObjectRetentionPolicyToContextModel(policy)}, Checks: []verificationdomain.VerifyCheck{{Name: "check", Result: "passed"}}, Assumptions: []string{"assumption"}, Limitations: []string{"limitation"}, GeneratedAt: now}
	legacy := SigningCustodyReviewFromContextModel(report)
	if legacy.ReportType != report.ReportType || legacy.TenantID != report.TenantID || !reflect.DeepEqual(legacy.SigningProviders, []SigningProvider{provider}) || !reflect.DeepEqual(legacy.ObjectRetentionPolicies, []ObjectRetentionPolicy{policy}) || !legacy.GeneratedAt.Equal(now) {
		t.Fatalf("report changed %#v", legacy)
	}
	legacy.Checks[0].Result = "changed"
	legacy.Assumptions[0] = "changed"
	legacy.Limitations[0] = "changed"
	*legacy.ObjectRetentionPolicies[0].VerificationLegalHold = false
	if report.Checks[0].Result != "passed" || report.Assumptions[0] != "assumption" || report.Limitations[0] != "limitation" || !*report.ObjectRetentionPolicies[0].VerificationLegalHold {
		t.Fatal("report shares mutable values")
	}
}
