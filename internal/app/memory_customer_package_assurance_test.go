package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestMemoryCustomerPackageReadinessUsesCanonicalFactsWithoutWritingReceipts(t *testing.T) {
	tx := memoryCustomerGovernanceFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := readMemoryReadinessSnapshot(t.Context(), &tx.state, "tenant", "tenant-release", fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := riskapp.EvaluateReadinessSnapshot(facts, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	var want []packagedomain.PolicyCheckSnapshot
	for _, c := range evaluation.Checks {
		want = append(want, packagedomain.PolicyCheckSnapshot{Name: c.Name, Result: c.Result, Severity: c.Severity, Missing: append([]string(nil), c.Missing...), Explanation: c.Explanation, Remediation: c.Remediation})
	}
	b := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	got, err := readMemoryCustomerPackageReadiness(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), b)
	if err != nil || !reflect.DeepEqual(got, want) || len(got) == 0 || b.remainingBytes >= packageapp.MaxCustomerPackageManifestBytes {
		t.Fatal("canonical readiness checks changed", got, err)
	}
	for i := range got {
		if len(got[i].Missing) > 0 {
			got[i].Missing[0] = "changed"
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("readiness read/caller mutation changed storage")
	}
	if v, err := readMemoryCustomerPackageReadiness(t.Context(), &tx.state, "tenant", "tenant-product", "", fixedNow(), b); err != nil || v != nil {
		t.Fatal("product-only readiness changed", v, err)
	}
	if v, err := readMemoryCustomerPackageReadiness(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), &memoryCustomerSnapshotBudget{remainingBytes: 1}); !errors.Is(err, ErrConflict) || v != nil {
		t.Fatal("over-budget readiness returned", err)
	}
}

func memoryCustomerRetentionFixture(t *testing.T) *memoryUnitOfWork {
	t.Helper()
	tx := memoryCustomerCatalogFixture(t)
	for _, row := range []struct {
		id, tenant, status string
		expiry             time.Time
	}{{"a-configured", "tenant", "configured", fixedNow().Add(time.Hour)}, {"b-expired", "tenant", "verified", fixedNow()}, {"c-fresh", "tenant", "verified", fixedNow().Add(time.Hour)}, {"foreign-policy", "foreign", "verified", fixedNow().Add(time.Hour)}} {
		p := domain.ObjectRetentionPolicy{ID: row.id, TenantID: row.tenant, Name: row.id, ObjectPrefix: "private-prefix-marker", ObjectKey: "private-key-marker", VerificationBucket: "private-bucket-marker", Mode: "COMPLIANCE", RetentionDays: 30, Status: row.status, VerificationProvider: "minio", VerificationMode: "COMPLIANCE", VerificationRetentionDays: 30, VerifiedAt: timePtr(fixedNow()), VerificationObservedAt: timePtr(fixedNow().Add(-time.Hour)), VerificationExpiresAt: timePtr(row.expiry), VerificationChecks: []domain.VerifyCheck{{Name: "provider", Result: "passed", Detail: "recorded"}}, VerificationLimitations: []string{"recorded scope"}, CreatedAt: fixedNow()}
		tx.state.ObjectRetentionPolicies[p.ID] = p
	}
	return tx
}

func TestMemoryCustomerPackageRetentionKeepsCanonicalExpiryAndRedactsStorageLocations(t *testing.T) {
	tx := memoryCustomerRetentionFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	b := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	v, err := readMemoryCustomerPackageRetention(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), b)
	if err != nil || len(v) != 3 {
		t.Fatal("owned retention proofs missing", v, err)
	}
	if v[0]["status"] != "configured" || v[1]["status"] == "verified" || v[2]["status"] != "verified" || v[2]["object_prefix_configured"] != true || v[2]["sample_object_key_configured"] != true {
		t.Fatal("configuration was upgraded or expiry ignored", v)
	}
	var want []map[string]any
	for _, id := range []string{"a-configured", "b-expired", "c-fresh"} {
		want = append(want, verificationapp.ObjectLockProofs([]verificationdomain.ObjectRetentionPolicy{domain.ObjectRetentionPolicyToContextModel(tx.state.ObjectRetentionPolicies[id])}, fixedNow())...)
	}
	if !reflect.DeepEqual(v, want) {
		t.Fatal("canonical proof representation changed", v, want)
	}
	raw, err := json.Marshal(v)
	if err != nil || strings.Contains(string(raw), "private-") || strings.Contains(string(raw), "foreign-policy") {
		t.Fatal("storage locations or foreign policy exported", err)
	}
	v[2]["verification_limitations"].([]string)[0] = "changed"
	v[2]["verification_checks"].([]map[string]any)[0]["detail"] = "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("retention read/caller mutation changed storage")
	}
	used := packageapp.MaxCustomerPackageManifestBytes - b.remainingBytes
	short := &memoryCustomerSnapshotBudget{remainingBytes: used - 1}
	if v, err := readMemoryCustomerPackageRetention(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), short); !errors.Is(err, ErrConflict) || v != nil || short.remainingBytes != used-1 {
		t.Fatal("partial over-budget proof published", err)
	}
}

func TestMemoryCustomerPackageAssuranceRejectsInvalidScopeTimeAndMetadata(t *testing.T) {
	tx := memoryCustomerRetentionFixture(t)
	for _, scope := range [][3]string{{"tenant", "foreign-product", ""}, {"foreign", "tenant-product", "tenant-release"}, {"tenant", "tenant-product", "sibling-release"}} {
		b := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		if v, err := readMemoryCustomerPackageRetention(t.Context(), &tx.state, scope[0], scope[1], scope[2], fixedNow(), b); !errors.Is(err, ErrNotFound) || v != nil {
			t.Fatal("foreign scope returned retention", err)
		}
		if v, err := readMemoryCustomerPackageReadiness(t.Context(), &tx.state, scope[0], scope[1], scope[2], fixedNow(), b); !errors.Is(err, ErrNotFound) || v != nil {
			t.Fatal("foreign scope returned readiness", err)
		}
	}
	for _, change := range []struct {
		name string
		edit func(*domain.ObjectRetentionPolicy)
	}{{"name", func(p *domain.ObjectRetentionPolicy) { p.Name = strings.Repeat("x", 4097) }}, {"negative", func(p *domain.ObjectRetentionPolicy) { p.RetentionDays = -1 }}, {"details", func(p *domain.ObjectRetentionPolicy) { p.VerificationChecks = make([]domain.VerifyCheck, 4097) }}, {"date", func(p *domain.ObjectRetentionPolicy) {
		p.VerificationExpiresAt = timePtr(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
	}}} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerRetentionFixture(t)
			p := tx.state.ObjectRetentionPolicies["c-fresh"]
			change.edit(&p)
			tx.state.ObjectRetentionPolicies[p.ID] = p
			b := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readMemoryCustomerPackageRetention(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), b)
			if !errors.Is(err, ErrConflict) || v != nil || b.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
				t.Fatal("invalid retention metadata returned", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readMemoryCustomerPackageRetention(ctx, &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("cancelled proof returned", err)
	}
}
