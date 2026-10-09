package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func memorySigningCustodyFixture(t *testing.T) (*memoryUnitOfWork, verificationquery.SigningCustodyReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Integrity.(verificationquery.SigningCustodyReader)
	if !ok {
		t.Fatal("memory integrity lacks focused signing-custody snapshot reader")
	}
	return tx, reader
}

func memorySigningCustodyRecords() (domain.SigningProvider, domain.ObjectRetentionPolicy) {
	at := fixedNow()
	expires := at.Add(time.Hour)
	hold := true
	provider := domain.SigningProvider{ID: "provider", TenantID: "tenant", Name: "HSM profile", Type: "native_pkcs11_hsm", Status: "active", KeyRef: "pkcs11:object=fixture", Encrypted: true, SchemaVersion: "1", CreatedAt: at}
	policy := domain.ObjectRetentionPolicy{ID: "policy", TenantID: "tenant", Name: "Retention", ObjectPrefix: "tenants/tenant/", ObjectKey: "tenants/tenant/object", RequireLegalHold: true, Mode: "governance", RetentionDays: 7, MaxVerificationAgeHours: 24, Status: "verified", VerifiedAt: &at, VerificationHash: "recorded", VerificationChecks: []domain.VerifyCheck{{Name: "recorded", Result: "passed", Detail: "provider receipt"}}, VerificationLimitations: []string{"operator review required"}, VerificationProvider: "provider", VerificationBucket: "fixture", VerificationMode: "governance", VerificationRetentionDays: 7, VerificationLegalHold: &hold, VerificationObservedAt: &at, VerificationExpiresAt: &expires, SchemaVersion: "1", CreatedAt: at}
	return provider, policy
}

func TestMemorySigningCustodySnapshotRetainsOwnedPublicRecordsAndDetachedReceipts(t *testing.T) {
	tx, reader := memorySigningCustodyFixture(t)
	provider, policy := memorySigningCustodyRecords()
	tx.state.SigningProviders[provider.ID] = provider
	tx.state.ObjectRetentionPolicies[policy.ID] = policy
	foreign := provider
	foreign.ID, foreign.TenantID, foreign.Name = "foreign", "foreign", strings.Repeat("ignored", 1300000)
	tx.state.SigningProviders[foreign.ID] = foreign
	tx.state.SigningKeys["private"] = domain.SigningKey{ID: "private", TenantID: "tenant", Private: []byte(strings.Repeat("private-key", 900000))}
	before := domain.ObjectRetentionPolicyFromContextModel(domain.ObjectRetentionPolicyToContextModel(policy))
	snapshot, err := reader.ReadSigningCustodySnapshot(t.Context(), "tenant")
	want := verificationapp.SigningCustodySnapshot{TenantID: "tenant", SigningProviders: []verificationdomain.SigningProvider{domain.SigningProviderToContextModel(provider)}, ObjectRetentionPolicies: []verificationdomain.ObjectRetentionPolicy{domain.ObjectRetentionPolicyToContextModel(policy)}}
	if err != nil || !reflect.DeepEqual(snapshot, want) {
		t.Fatal("custody snapshot lost public fields, ownership or receipt metadata", err)
	}
	snapshot.ObjectRetentionPolicies[0].VerificationChecks[0].Detail = "changed"
	snapshot.ObjectRetentionPolicies[0].VerificationLimitations[0] = "changed"
	*snapshot.ObjectRetentionPolicies[0].VerificationLegalHold = false
	*snapshot.ObjectRetentionPolicies[0].VerificationExpiresAt = fixedNow().AddDate(1, 0, 0)
	if !reflect.DeepEqual(tx.state.ObjectRetentionPolicies[policy.ID], before) {
		t.Fatal("custody receipt aliases immutable repository state")
	}
	query, err := verificationquery.NewSigningCustody(reader, func() time.Time { return fixedNow().Add(2 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	report, err := query.Report(t.Context(), domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"keys:admin"}})
	if err != nil || report.ObjectRetentionPolicies[0].Status != "stale" || report.Checks[0].Result != "passed" || report.Checks[1].Result != "passed" || report.Checks[2].Result != "failed" || len(report.Limitations) == 0 || len(report.Assumptions) == 0 || tx.state.ObjectRetentionPolicies[policy.ID].Status != "verified" {
		t.Fatal("focused report lost stale receipt checks, limitations or immutability", err)
	}
}

func TestMemorySigningCustodySnapshotEnforcesCombinedRecordLimitWithoutTruncation(t *testing.T) {
	tx, reader := memorySigningCustodyFixture(t)
	provider, policy := memorySigningCustodyRecords()
	for i := range 2048 {
		p, r := provider, policy
		p.ID, r.ID = fmt.Sprintf("provider-%04d", i), fmt.Sprintf("policy-%04d", i)
		tx.state.SigningProviders[p.ID], tx.state.ObjectRetentionPolicies[r.ID] = p, r
	}
	snapshot, err := reader.ReadSigningCustodySnapshot(t.Context(), "tenant")
	if err != nil || len(snapshot.SigningProviders) != 2048 || len(snapshot.ObjectRetentionPolicies) != 2048 {
		t.Fatal("exact combined record limit was rejected or truncated", err)
	}
	tx.state.SigningProviders[provider.ID] = provider
	if v, err := reader.ReadSigningCustodySnapshot(t.Context(), "tenant"); !errors.Is(err, verificationquery.ErrSigningCustodyProjection) || !reflect.DeepEqual(v, verificationapp.SigningCustodySnapshot{}) {
		t.Fatal("combined record overflow exposed partial snapshot", err)
	}
}

func TestMemorySigningCustodySnapshotEnforcesPublicEncodedByteLimit(t *testing.T) {
	tx, reader := memorySigningCustodyFixture(t)
	provider, policy := memorySigningCustodyRecords()
	provider.Name = ""
	p, _ := json.Marshal(provider)
	r, _ := json.Marshal(policy)
	provider.Name = strings.Repeat("x", verificationquery.MaxSigningCustodyBytes-len(p)-len(r))
	tx.state.SigningProviders[provider.ID], tx.state.ObjectRetentionPolicies[policy.ID] = provider, policy
	if _, err := reader.ReadSigningCustodySnapshot(t.Context(), "tenant"); err != nil {
		t.Fatal("exact typed public byte budget rejected", err)
	}
	provider.Name += "x"
	tx.state.SigningProviders[provider.ID] = provider
	if v, err := reader.ReadSigningCustodySnapshot(t.Context(), "tenant"); !errors.Is(err, verificationquery.ErrSigningCustodyProjection) || !reflect.DeepEqual(v, verificationapp.SigningCustodySnapshot{}) {
		t.Fatal("combined public byte overflow exposed partial snapshot", err)
	}
	var missingContext context.Context
	if _, err := reader.ReadSigningCustodySnapshot(missingContext, "tenant"); err == nil {
		t.Fatal("nil context was accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.ReadSigningCustodySnapshot(ctx, "tenant"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not propagated", err)
	}
	if _, err := reader.ReadSigningCustodySnapshot(t.Context(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing tenant was accepted", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadSigningCustodySnapshot(t.Context(), "tenant"); err == nil {
		t.Fatal("closed transaction returned custody metadata")
	}
}
