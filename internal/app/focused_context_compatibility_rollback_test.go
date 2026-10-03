package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestFocusedContextCompatibilityWritesRestoreCachesAfterPersistenceFailure(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	store := &failingParserReleaseStore{err: errors.New("persistence unavailable")}
	ledger.store = store
	beforeAudit := len(ledger.chain[actor.TenantID])

	if _, err := ledger.CreateRedactionProfile(ctx, actor, CreateRedactionProfileInput{Name: "customer", AllowedTypes: []string{"sbom"}}); !errors.Is(err, store.err) {
		t.Fatalf("redaction profile persistence error = %v", err)
	}
	if len(ledger.redactions) != 0 || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatalf("failed package write was published: profiles=%#v audit=%#v", ledger.redactions, ledger.chain[actor.TenantID])
	}

	if _, err := ledger.CreateCustomReportTemplate(ctx, actor, CreateReportTemplateInput{
		Name: "release", Version: "v1", ReportType: "summary", AllowedFields: []string{"subject_id"},
	}); !errors.Is(err, store.err) {
		t.Fatalf("report template persistence error = %v", err)
	}
	if len(ledger.reportTemplates) != 0 || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatalf("failed report write was published: templates=%#v audit=%#v", ledger.reportTemplates, ledger.chain[actor.TenantID])
	}

	if _, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{
		Name: "HSM", Type: "native_pkcs11_hsm", KeyRef: "pkcs11:token=signing;object=release-key", Encrypted: true,
	}); !errors.Is(err, store.err) {
		t.Fatalf("signing provider persistence error = %v", err)
	}
	if len(ledger.signingProviders) != 0 || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatalf("failed verification write was published: providers=%#v audit=%#v", ledger.signingProviders, ledger.chain[actor.TenantID])
	}

	if _, err := ledger.CreateWaiver(ctx, actor, CreateWaiverInput{
		ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "low", Reason: "temporary", ExpiresAt: fixedNow().Add(time.Hour),
	}); !errors.Is(err, store.err) {
		t.Fatalf("waiver persistence error = %v", err)
	}
	if len(ledger.waivers) != 0 || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatalf("failed risk write was published: waivers=%#v audit=%#v", ledger.waivers, ledger.chain[actor.TenantID])
	}
}

func TestRiskContextCompatibilityConversionsPreservePolicyAndApprovalHistory(t *testing.T) {
	original := domain.PolicyEvaluation{
		ID: "pe_1", TenantID: "ten_1", ReleaseID: "rel_1", Result: "failed", PolicySet: "policy.v1", CreatedAt: fixedNow(),
		Checks: []domain.PolicyCheck{{Name: "critical_findings", Result: "failed", Severity: "critical", Missing: []string{"finding_1"}, Explanation: "finding requires triage", Remediation: "review finding"}},
	}
	converted := policyEvaluationToRiskContext(original)
	if converted.ID != original.ID || converted.Checks[0].Name != original.Checks[0].Name || !reflect.DeepEqual(converted.Checks[0].Missing, original.Checks[0].Missing) {
		t.Fatalf("risk conversion lost policy coordinates: %#v", converted)
	}
	converted.Checks[0].Missing[0] = "changed"
	if original.Checks[0].Missing[0] != "finding_1" {
		t.Fatalf("risk conversion aliased policy history: %#v", original)
	}
	cloned := cloneRiskPolicyEvaluationMap(map[string]domain.PolicyEvaluation{"pe_1": original})
	if !reflect.DeepEqual(cloned["pe_1"], original) {
		t.Fatalf("policy compatibility roundtrip changed history: got=%#v original=%#v", cloned["pe_1"], original)
	}
	value := cloned["pe_1"]
	value.Checks[0].Missing[0] = "changed"
	if original.Checks[0].Missing[0] != "finding_1" {
		t.Fatalf("policy clone aliased source history: %#v", original)
	}

	approvedAt := fixedNow()
	before := domain.Exception{ID: "ex_1", TenantID: "ten_1", Approved: true, ApprovedBy: "usr_1", ApprovedAt: &approvedAt}
	after := before
	if !sameExceptionApproval(before, after) {
		t.Fatal("identical approval history was treated as changed")
	}
	after.ApprovedBy = "usr_2"
	if sameExceptionApproval(before, after) {
		t.Fatal("changed approver was treated as identical")
	}
	after = before
	after.ApprovedAt = nil
	if sameExceptionApproval(before, after) {
		t.Fatal("removed approval time was treated as identical")
	}
}

func TestRiskContextReaderEnforcesTenantOwnershipAcrossLegacyResources(t *testing.T) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor, release, _ := setupReleaseRiskFixture(t, ledger)
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID: release.ProductID, ReleaseID: release.ID, Type: "security_review", Title: "Review", PayloadHash: sampleDigest("review"),
	})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	ledger.mu.Lock()
	ledger.vexDocuments["vex_1"] = domain.VEXDocument{ID: "vex_1", TenantID: actor.TenantID, ReleaseID: release.ID, EvidenceID: evidence.ID}
	ledger.controls["ctl_1"] = domain.SecurityControl{ID: "ctl_1", TenantID: actor.TenantID}
	ledger.customPolicies["pol_1"] = domain.CustomPolicy{ID: "pol_1", TenantID: actor.TenantID}
	ledger.contractDiffs["diff_1"] = domain.ContractDiff{ID: "diff_1", TenantID: actor.TenantID, ProductID: release.ProductID, ReleaseID: release.ID}
	ledger.waivers["wv_1"] = domain.Waiver{ID: "wv_1", TenantID: actor.TenantID, ScopeType: "release", ScopeID: release.ID}
	ledger.manualDocs["review_1"] = domain.ManualSecurityDocument{ID: "review_1", TenantID: actor.TenantID, ProductID: release.ProductID, ReleaseID: release.ID, DocumentType: "security_review"}
	ledger.customerPackages["pkg_1"] = domain.CustomerSecurityPackage{ID: "pkg_1", TenantID: actor.TenantID, ProductID: release.ProductID, ReleaseID: release.ID}
	ledger.exceptions["ex_1"] = domain.Exception{ID: "ex_1", TenantID: actor.TenantID, ReleaseID: release.ID, Reason: "temporary", Owner: "security", ExpiresAt: fixedNow().Add(time.Hour)}
	ledger.exceptions["ex_foreign"] = domain.Exception{ID: "ex_foreign", TenantID: "ten_foreign", ReleaseID: release.ID}
	ledger.mu.Unlock()
	reader := ledgerRiskReader{ledger: ledger}
	if product, err := reader.GetProduct(ctx, actor.TenantID, release.ProductID); err != nil || product.ID != release.ProductID {
		t.Fatalf("owned product = %#v, %v", product, err)
	}
	if got, err := reader.GetRelease(ctx, actor.TenantID, release.ID); err != nil || got.ProductID != release.ProductID {
		t.Fatalf("owned release = %#v, %v", got, err)
	}
	if got, err := reader.GetEvidence(ctx, actor.TenantID, evidence.ID); err != nil || got.ReleaseID != release.ID {
		t.Fatalf("owned evidence = %#v, %v", got, err)
	}
	if got, err := reader.GetVEX(ctx, actor.TenantID, "vex_1"); err != nil || got.EvidenceID != evidence.ID {
		t.Fatalf("owned VEX = %#v, %v", got, err)
	}
	if got, err := reader.GetControl(ctx, actor.TenantID, "ctl_1"); err != nil || got.ID != "ctl_1" {
		t.Fatalf("owned control = %#v, %v", got, err)
	}
	if subject, err := reader.ResolveGovernanceSubject(ctx, actor.TenantID, "release", release.ID); err != nil || subject.ProductID != release.ProductID {
		t.Fatalf("owned governance subject = %#v, %v", subject, err)
	}
	for _, coordinate := range []struct{ kind, id string }{{"control", "ctl_1"}, {"policy", "pol_1"}, {"contract_diff", "diff_1"}, {"waiver", "wv_1"}, {"security_review", "review_1"}, {"customer_package", "pkg_1"}} {
		subject, err := reader.ResolveGovernanceSubject(ctx, actor.TenantID, coordinate.kind, coordinate.id)
		if err != nil || subject.ID != coordinate.id || subject.TenantID != actor.TenantID {
			t.Fatalf("owned governance subject %s/%s = %#v, %v", coordinate.kind, coordinate.id, subject, err)
		}
		if _, err := reader.ResolveGovernanceSubject(ctx, "ten_foreign", coordinate.kind, coordinate.id); !errors.Is(err, riskapp.ErrNotFound) {
			t.Fatalf("foreign governance subject %s/%s = %v", coordinate.kind, coordinate.id, err)
		}
	}
	if exceptions, err := reader.ListExceptions(ctx, actor.TenantID); err != nil || len(exceptions) != 1 || exceptions[0].ID != "ex_1" {
		t.Fatalf("tenant exceptions = %#v, %v", exceptions, err)
	}
	if snapshot, err := reader.ReadReleaseReadinessSnapshot(ctx, actor.TenantID, release.ID); err != nil || snapshot.TenantID != actor.TenantID || snapshot.ReleaseID != release.ID || len(snapshot.IncompleteExceptionIDs) != 0 {
		t.Fatalf("readiness snapshot = %#v, %v", snapshot, err)
	}
	ledger.mu.Lock()
	tx := newLedgerRiskTransaction(ledger)
	if product, err := tx.GetProduct(ctx, actor.TenantID, release.ProductID); err != nil || product.ID != release.ProductID {
		t.Fatalf("transactional product = %#v, %v", product, err)
	}
	if exceptions, err := tx.ListExceptions(ctx, actor.TenantID); err != nil || len(exceptions) != 1 || exceptions[0].ID != "ex_1" {
		t.Fatalf("transactional tenant exceptions = %#v, %v", exceptions, err)
	}
	if snapshot, err := tx.ReadReleaseReadinessSnapshot(ctx, actor.TenantID, release.ID); err != nil || snapshot.TenantID != actor.TenantID || snapshot.ReleaseID != release.ID {
		t.Fatalf("transactional readiness = %#v, %v", snapshot, err)
	}
	if _, err := tx.GetProduct(ctx, "ten_foreign", release.ProductID); !errors.Is(err, riskapp.ErrNotFound) {
		t.Fatalf("transactional foreign product = %v", err)
	}
	ledger.mu.Unlock()
	for _, check := range []struct {
		name string
		read func() error
	}{
		{"product", func() error { _, err := reader.GetProduct(ctx, "ten_foreign", release.ProductID); return err }},
		{"release", func() error { _, err := reader.GetRelease(ctx, "ten_foreign", release.ID); return err }},
		{"evidence", func() error { _, err := reader.GetEvidence(ctx, "ten_foreign", evidence.ID); return err }},
		{"VEX", func() error { _, err := reader.GetVEX(ctx, "ten_foreign", "vex_1"); return err }},
		{"control", func() error { _, err := reader.GetControl(ctx, "ten_foreign", "ctl_1"); return err }},
		{"governance subject", func() error {
			_, err := reader.ResolveGovernanceSubject(ctx, "ten_foreign", "release", release.ID)
			return err
		}},
		{"readiness snapshot", func() error {
			_, err := reader.ReadReleaseReadinessSnapshot(ctx, "ten_foreign", release.ID)
			return err
		}},
	} {
		t.Run(check.name, func(t *testing.T) {
			if err := check.read(); !errors.Is(err, riskapp.ErrNotFound) {
				t.Fatalf("foreign tenant read = %v, want not found", err)
			}
		})
	}
}
