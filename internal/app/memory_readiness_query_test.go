package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

type memoryReadinessQueryReader interface {
	ReadReleaseReadinessSnapshotAt(context.Context, string, string, time.Time) (riskapp.ReadinessSnapshot, error)
}

func memoryReadinessQueryFixture(t *testing.T) (*memoryUnitOfWork, memoryReadinessQueryReader) {
	t.Helper()
	tx, _ := memoryAnomalyFixture(t)
	r, ok := tx.Repositories().Decisions.(memoryReadinessQueryReader)
	if !ok {
		t.Fatal("memory risk repository lacks native readiness fact reader")
	}
	if _, ok := tx.Repositories().Decisions.(riskquery.ReleaseReadinessReader); !ok {
		t.Fatal("native readiness query port is missing")
	}
	tx.state.CustomerPackages = map[string]domain.CustomerSecurityPackage{}
	e := tx.state.Evidence["tenant-evidence"]
	e.Type = "sbom"
	tx.state.Evidence[e.ID] = e
	high := tx.state.VulnerabilityScans["scan"]
	high.Findings = append(high.Findings, domain.VulnerabilityFinding{ID: "high", Vulnerability: "CVE-high", Component: "component", Severity: "high", State: "open"})
	tx.state.VulnerabilityScans[high.ID] = high
	return tx, r
}

func TestMemoryReadinessQueryUsesOwnedTrustFactsAndDetachedBoundedIdentifiers(t *testing.T) {
	tx, r := memoryReadinessQueryFixture(t)
	tx.state.Decisions["decision"] = domain.VulnerabilityDecision{ID: "decision", TenantID: "tenant", ReleaseID: "tenant-release", ScanID: "scan", FindingID: "finding", Vulnerability: "CVE-fixture", Component: "component", Status: "not_affected", CustomerVisible: true, InternalNotes: strings.Repeat("private", 10000)}
	tx.state.Exceptions["exception"] = domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "tenant-release", FindingID: "high", Approved: true, ExpiresAt: fixedNow().Add(time.Hour)}
	tx.state.RedactionProfiles["profile"] = domain.RedactionProfile{ID: "profile", TenantID: "tenant", AllowedTypes: []string{"sbom"}, ExcludedFields: []string{"payload_ref", "object_key", "private_key", "token", "secret", "internal_notes"}}
	tx.state.CustomerPackages["package"] = domain.CustomerSecurityPackage{ID: "package", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", RedactionProfileID: "profile", ExpiresAt: fixedNow().Add(time.Hour), Manifest: map[string]any{"private": strings.Repeat("private", 10000)}}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	want := riskapp.ReadinessSnapshot{SnapshotVersion: riskapp.ReadinessSnapshotVersion, TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", HasArtifact: true, HasArtifactDigest: true, HasSBOM: true, HasVulnerabilityScan: true, HasPassedBuild: true, HasVerifiedBuildAttestation: true, MissingCustomerStatementIDs: []string{"decision"}, MissingNotAffectedReasonIDs: []string{"decision"}, IncompleteExceptionIDs: []string{"exception"}, PackageCount: 1}
	got, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("readiness did not select exact current trusted facts", got, err)
	}
	got.MissingCustomerStatementIDs[0], got.MissingNotAffectedReasonIDs[0], got.IncompleteExceptionIDs[0] = "changed", "changed", "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("readiness reads or caller mutations changed stored state")
	}
	got, err = r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow().Add(2*time.Hour))
	if err != nil || !got.UnhandledHigh || !reflect.DeepEqual(got.InvalidPackageOrProfileIDs, []string{"package"}) {
		t.Fatal("explicit evaluation time did not expire exception/package", got, err)
	}
}

func TestMemoryReadinessQueryRejectsFalseTrustForeignFactsAndIdentifierOverflow(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		change                             func(*MemoryUnitOfWorkSnapshot)
		build, attestation, critical, high bool
	}{
		{"foreign-artifact", func(s *MemoryUnitOfWorkSnapshot) {
			a := s.Artifacts["artifact"]
			a.TenantID = "foreign"
			s.Artifacts[a.ID] = a
		}, false, false, true, true},
		{"unregistered-reference", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Artifacts, "artifact") }, false, false, true, true},
		{"foreign-receipt", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VerificationResults["receipt"]
			v.TenantID = "foreign"
			s.VerificationResults[v.ID] = v
		}, true, false, true, true},
		{"foreign-scan-source", func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["scan-source"]
			e.TenantID = "foreign"
			s.Evidence[e.ID] = e
		}, true, true, false, false},
		{"ambiguous-decision", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["scan"]
			v.Findings = append(v.Findings, v.Findings[0])
			s.VulnerabilityScans[v.ID] = v
			s.Decisions["d"] = domain.VulnerabilityDecision{ID: "d", TenantID: "tenant", ReleaseID: "tenant-release", ScanID: "scan", FindingID: "finding", Vulnerability: "CVE-fixture", Component: "component", Status: "fixed"}
		}, true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, r := memoryReadinessQueryFixture(t)
			tc.change(&tx.state)
			v, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow())
			if err != nil || v.HasPassedBuild != tc.build || v.HasVerifiedBuildAttestation != tc.attestation || v.UnhandledCritical != tc.critical || v.UnhandledHigh != tc.high {
				t.Fatal("false/foreign readiness trust", v, err)
			}
		})
	}
	tx, r := memoryReadinessQueryFixture(t)
	for i := 0; i < 2049; i++ {
		id := fmt.Sprintf("decision-%04d", i)
		tx.state.Decisions[id] = domain.VulnerabilityDecision{ID: id, TenantID: "tenant", ReleaseID: "tenant-release", ScanID: "scan", FindingID: "finding", Vulnerability: "CVE-fixture", Component: "component", Status: "not_affected", CustomerVisible: true}
	}
	if v, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow()); !errors.Is(err, riskapp.ErrValidation) || !reflect.DeepEqual(v, riskapp.ReadinessSnapshot{}) {
		t.Fatal("combined identifier overflow was truncated or returned partial facts", v, err)
	}
}

func TestMemoryReadinessQueryVerifiesOnlyCurrentOwnedHistoricalBundleSignatures(t *testing.T) {
	tx, r := memoryReadinessQueryFixture(t)
	pub, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := "sha256:" + strings.Repeat("a", 64)
	tx.state.ReleaseBundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "tenant-release", ManifestHash: hash, SignatureRefs: []string{"signature"}}
	tx.state.SigningKeys["key"] = domain.SigningKey{ID: "key", TenantID: "tenant", Algorithm: "Ed25519", Status: "active", PublicKey: base64.RawStdEncoding.EncodeToString(pub), ValidFrom: fixedNow().Add(-time.Hour), CreatedAt: fixedNow().Add(-time.Hour), Private: []byte("private-key-not-selected")}
	tx.state.Signatures["signature"] = domain.Signature{ID: "signature", TenantID: "tenant", SubjectType: "release_bundle", SubjectID: "bundle", KeyID: "key", Algorithm: "Ed25519", Value: base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte(hash))), CreatedAt: fixedNow()}
	for _, tc := range []struct {
		name   string
		mutate func()
		want   bool
	}{
		{"valid", func() {}, true},
		{"wrong-subject", func() { v := tx.state.Signatures["signature"]; v.SubjectID = "other"; tx.state.Signatures[v.ID] = v }, false},
		{"foreign-key", func() {
			v := tx.state.Signatures["signature"]
			v.SubjectID = "bundle"
			tx.state.Signatures[v.ID] = v
			k := tx.state.SigningKeys["key"]
			k.TenantID = "foreign"
			tx.state.SigningKeys[k.ID] = k
		}, false},
		{"compromised", func() {
			k := tx.state.SigningKeys["key"]
			k.TenantID = "tenant"
			k.Status, k.RevocationSemantics, k.HistoricalValidityPolicy = "revoked", "compromised", "invalidate_all"
			tx.state.SigningKeys[k.ID] = k
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.mutate()
			v, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow())
			if err != nil || v.HasVerifiedSignedBundle != tc.want {
				t.Fatal("bundle trust lost subject/tenant/key-lifecycle binding", v, err)
			}
		})
	}
}

func TestMemoryReadinessQueryRejectsMissingParentsCancellationAndClosedTransactions(t *testing.T) {
	tx, r := memoryReadinessQueryFixture(t)
	for _, tenant := range []string{"foreign", "missing"} {
		if v, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), tenant, "tenant-release", fixedNow()); !errors.Is(err, riskapp.ErrNotFound) || !reflect.DeepEqual(v, riskapp.ReadinessSnapshot{}) {
			t.Fatal("foreign facts returned", v, err)
		}
	}
	v := tx.state.Releases["tenant-release"]
	v.ProductID = "foreign-product"
	tx.state.Releases[v.ID] = v
	if _, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", v.ID, fixedNow()); !errors.Is(err, riskapp.ErrNotFound) {
		t.Fatal("foreign parent accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.ReadReleaseReadinessSnapshotAt(ctx, "tenant", v.ID, fixedNow()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled fact read proceeded", err)
	}
	var absent context.Context
	if _, err := r.ReadReleaseReadinessSnapshotAt(absent, "tenant", v.ID, fixedNow()); !errors.Is(err, riskapp.ErrValidation) {
		t.Fatal("absent context accepted", err)
	}
	if _, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", v.ID, time.Time{}); !errors.Is(err, riskapp.ErrValidation) {
		t.Fatal("zero evaluation time accepted", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", v.ID, fixedNow()); !errors.Is(err, ErrConflict) {
		t.Fatal("closed fact transaction returned data", err)
	}
}

func TestMemoryReadinessQueryPackageIdentifierBudgetIsNotCountedTwice(t *testing.T) {
	tx, r := memoryReadinessQueryFixture(t)
	for i := 0; i < 4096; i++ {
		id := fmt.Sprintf("package-%04d", i)
		tx.state.CustomerPackages[id] = domain.CustomerSecurityPackage{ID: id, TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", RedactionProfileID: "missing", ExpiresAt: fixedNow().Add(time.Hour)}
	}
	v, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow())
	if err != nil || v.PackageCount != 4096 || len(v.InvalidPackageOrProfileIDs) != 4096 || v.InvalidPackageOrProfileIDs[0] != "package-0000" || v.InvalidPackageOrProfileIDs[4095] != "package-4095" {
		t.Fatal("valid shared-budget boundary was counted twice or truncated", v.PackageCount, len(v.InvalidPackageOrProfileIDs), err)
	}
}

type fixedMemoryReadinessQuery struct {
	memoryReadinessQueryReader
	at time.Time
}

func (r fixedMemoryReadinessQuery) ReadReleaseReadinessSnapshot(ctx context.Context, tenant, release string) (riskapp.ReadinessSnapshot, error) {
	return r.ReadReleaseReadinessSnapshotAt(ctx, tenant, release, r.at)
}

func TestMemoryReadinessQueryRunsFocusedPolicyWithCurrentGrantsWithoutEffects(t *testing.T) {
	tx, reader := memoryReadinessQueryFixture(t)
	query, err := riskquery.NewReleaseReadinessQuery(fixedMemoryReadinessQuery{reader, fixedNow()}, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"verify:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "release", ResourceID: "tenant-release", Scopes: []string{"verify:read"}}}}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := query.Preview(t.Context(), actor, "tenant-release")
	if err != nil || evaluation.ID != "" || evaluation.TenantID != "tenant" || evaluation.ReleaseID != "tenant-release" || len(evaluation.Checks) != 13 || evaluation.Result != "failed" {
		t.Fatal("native readiness did not evaluate the complete policy without a receipt", evaluation, err)
	}
	actor.ResourceGrants = nil
	if _, err := query.Preview(t.Context(), actor, "tenant-release"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed readiness grant still allowed query", err)
	}
	actor.KeyID, actor.UserID = "foreign-key", ""
	actor.TenantID = "foreign"
	if _, err := query.Preview(t.Context(), actor, "tenant-release"); !errors.Is(err, riskapp.ErrNotFound) {
		t.Fatal("foreign actor reached readiness facts", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("query preview/denial persisted policy, audit, replay or other effects")
	}
}

func TestMemoryReadinessQueryRejectsSignatureCandidateAndSelectedValueOverflow(t *testing.T) {
	tx, r := memoryReadinessQueryFixture(t)
	tx.state.SigningKeys["key"] = domain.SigningKey{ID: "key", TenantID: "tenant", Algorithm: "Ed25519", Status: "active", PublicKey: "invalid-but-bounded", CreatedAt: fixedNow()}
	tx.state.Signatures["signature"] = domain.Signature{ID: "signature", TenantID: "tenant", SubjectType: "release_bundle", SubjectID: "bundle", KeyID: "key", Algorithm: "Ed25519", Value: "invalid-but-bounded", CreatedAt: fixedNow()}
	refs := make([]string, 257)
	for i := range refs {
		refs[i] = "signature"
	}
	tx.state.ReleaseBundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "tenant-release", ManifestHash: "sha256:" + strings.Repeat("a", 64), SignatureRefs: refs}
	if v, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow()); !errors.Is(err, riskapp.ErrValidation) || !reflect.DeepEqual(v, riskapp.ReadinessSnapshot{}) {
		t.Fatal("signature candidate overflow produced partial/false facts", v, err)
	}
	b := tx.state.ReleaseBundles["bundle"]
	b.SignatureRefs = refs[:1]
	tx.state.ReleaseBundles[b.ID] = b
	k := tx.state.SigningKeys["key"]
	k.PublicKey = strings.Repeat("x", 257)
	tx.state.SigningKeys[k.ID] = k
	if v, err := r.ReadReleaseReadinessSnapshotAt(t.Context(), "tenant", "tenant-release", fixedNow()); !errors.Is(err, riskapp.ErrValidation) || !reflect.DeepEqual(v, riskapp.ReadinessSnapshot{}) {
		t.Fatal("oversized selected public key produced partial facts", v, err)
	}
}
