package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func memoryGovernanceReadFixture(t *testing.T) (*MemoryUnitOfWorkFactory, *memoryUnitOfWork) {
	t.Helper()
	factory := NewMemoryUnitOfWorkFactory()
	uow, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tx := uow.(*memoryUnitOfWork)
	now := fixedNow()
	for _, tenant := range []string{"tenant", "foreign"} {
		tx.state.Tenants[tenant] = domain.Tenant{ID: tenant, Name: tenant, CreatedAt: now}
		product, release, framework, control, policy, evidence := tenant+"-product", tenant+"-release", tenant+"-framework", tenant+"-control", tenant+"-policy", tenant+"-evidence"
		tx.state.Products[product] = domain.Product{ID: product, TenantID: tenant}
		tx.state.Releases[release] = domain.Release{ID: release, TenantID: tenant, ProductID: product}
		tx.state.ControlFrameworks[framework] = domain.ControlFramework{ID: framework, TenantID: tenant}
		tx.state.SecurityControls[control] = domain.SecurityControl{ID: control, TenantID: tenant, FrameworkID: framework}
		tx.state.CustomPolicies[policy] = domain.CustomPolicy{ID: policy, TenantID: tenant}
		tx.state.Evidence[evidence] = domain.EvidenceItem{ID: evidence, TenantID: tenant, ProductID: product, ReleaseID: release, Type: "vulnerability_scan"}
		tx.state.VulnerabilityScans[tenant+"-scan"] = domain.VulnerabilityScan{ID: tenant + "-scan", TenantID: tenant, ReleaseID: release, EvidenceID: evidence, Findings: []domain.VulnerabilityFinding{{ID: tenant + "-finding", Vulnerability: "CVE-2026-1"}}}
		tx.state.Waivers[tenant+"-waiver"] = domain.Waiver{ID: tenant + "-waiver", TenantID: tenant, ScopeType: "release", ScopeID: release, Owner: "security", Risk: "reviewed", Reason: "reason", ExpiresAt: now.AddDate(0, 0, 1), Approved: true, ApprovedBy: "approver", ApprovedAt: &now, SchemaVersion: domain.WaiverSchemaVersion, CreatedAt: now}
		tx.state.Exceptions[tenant+"-exception"] = domain.Exception{ID: tenant + "-exception", TenantID: tenant, ReleaseID: release, FindingID: tenant + "-finding", ControlID: control, Reason: "reason", Owner: "security", ExpiresAt: now.AddDate(0, 0, 1), Approved: true, ApprovedBy: "approver", ApprovedAt: &now, CreatedAt: now}
		for _, suffix := range []string{"base", "target"} {
			id := tenant + "-contract-" + suffix
			tx.state.Evidence[id+"-evidence"] = domain.EvidenceItem{ID: id + "-evidence", TenantID: tenant, ProductID: product, ReleaseID: release, Type: "openapi_contract"}
			tx.state.OpenAPIContracts[id] = domain.OpenAPIContract{ID: id, TenantID: tenant, ProductID: product, ReleaseID: release, EvidenceID: id + "-evidence"}
		}
		tx.state.ContractDiffs[tenant+"-diff"] = domain.ContractDiff{ID: tenant + "-diff", TenantID: tenant, ProductID: product, ReleaseID: release, BaseContractID: tenant + "-contract-base", TargetContractID: tenant + "-contract-target"}
		tx.state.Evidence[tenant+"-review-evidence"] = domain.EvidenceItem{ID: tenant + "-review-evidence", TenantID: tenant, ProductID: product, ReleaseID: release, Type: "security_review"}
		tx.state.ManualSecurityDocuments[tenant+"-review"] = domain.ManualSecurityDocument{ID: tenant + "-review", TenantID: tenant, ProductID: product, ReleaseID: release, DocumentType: "security_review", EvidenceID: tenant + "-review-evidence"}
		tx.state.RedactionProfiles[tenant+"-redaction"] = domain.RedactionProfile{ID: tenant + "-redaction", TenantID: tenant}
		tx.state.CustomerPackages[tenant+"-package"] = domain.CustomerSecurityPackage{ID: tenant + "-package", TenantID: tenant, ProductID: product, ReleaseID: release, RedactionProfileID: tenant + "-redaction"}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	uow, err = factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tx = uow.(*memoryUnitOfWork)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return factory, tx
}

func TestMemoryGovernanceReadersExposeFocusedOwnedCoordinatesAndDetachedRecords(t *testing.T) {
	factory, tx := memoryGovernanceReadFixture(t)
	waivers, ok := tx.Repositories().Governance.(riskapp.WaiverCommandReader)
	if !ok {
		t.Fatal("memory governance lacks focused waiver reads")
	}
	exceptions, ok := tx.Repositories().Decisions.(riskapp.ExceptionCommandReader)
	if !ok {
		t.Fatal("memory decisions lack focused exception reads")
	}
	approvals, ok := tx.Repositories().Governance.(riskapp.ApprovalReader)
	if !ok {
		t.Fatal("memory governance lacks focused approval reads")
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	pendingBefore, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ kind, id, product, release string }{
		{"release", "tenant-release", "tenant-product", "tenant-release"},
		{"finding", "tenant-finding", "tenant-product", "tenant-release"},
		{"control", "tenant-control", "", ""},
		{"policy", "tenant-policy", "", ""},
	} {
		v, err := waivers.ReadWaiverSubject(t.Context(), "tenant", tc.kind, tc.id)
		want := riskapp.GovernanceSubjectReference{Type: tc.kind, ID: tc.id, TenantID: "tenant", ProductID: tc.product, ReleaseID: tc.release}
		if err != nil || v != want {
			t.Fatal("waiver subject lost owned coordinates", tc.kind, v, err)
		}
		if tc.kind != "policy" {
			v, err := exceptions.ReadExceptionSubject(t.Context(), "tenant", tc.kind, tc.id)
			if err != nil || v != want {
				t.Fatal("exception subject lost owned coordinates", tc.kind, v, err)
			}
		}
	}
	for _, tc := range []struct{ kind, id string }{{"release", "tenant-release"}, {"waiver", "tenant-waiver"}, {"contract_diff", "tenant-diff"}, {"security_review", "tenant-review"}, {"customer_package", "tenant-package"}} {
		v, err := approvals.ReadApprovalSubject(t.Context(), "tenant", tc.kind, tc.id)
		if err != nil || v.Type != tc.kind || v.ID != tc.id || v.TenantID != "tenant" || v.ProductID != "tenant-product" || v.ReleaseID != "tenant-release" {
			t.Fatal("approval subject lost its current parents", v, err)
		}
	}
	if exists, err := approvals.ApprovalEvidenceExists(t.Context(), "tenant", "tenant-evidence"); err != nil || !exists {
		t.Fatal("owned approval evidence is missing", err)
	}
	if exists, err := approvals.ApprovalEvidenceExists(t.Context(), "tenant", "foreign-evidence"); err != nil || exists {
		t.Fatal("approval evidence lookup leaked foreign existence", err)
	}
	waiver, err := waivers.ReadWaiverForApproval(t.Context(), "tenant", "tenant-waiver")
	if err != nil || !reflect.DeepEqual(domain.Waiver(waiver), tx.state.Waivers[waiver.ID]) {
		t.Fatal("full waiver read lost metadata", err)
	}
	exception, err := exceptions.ReadExceptionForApproval(t.Context(), "tenant", "tenant-exception")
	if err != nil || !reflect.DeepEqual(domain.Exception(exception), tx.state.Exceptions[exception.ID]) {
		t.Fatal("full exception read lost metadata", err)
	}
	*waiver.ApprovedAt, *exception.ApprovedAt = fixedNow().AddDate(1, 0, 0), fixedNow().AddDate(1, 0, 0)
	if !tx.state.Waivers[waiver.ID].ApprovedAt.Equal(fixedNow()) || !tx.state.Exceptions[exception.ID].ApprovedAt.Equal(fixedNow()) {
		t.Fatal("approval reads shared mutable stored timestamps")
	}
	if !reflect.DeepEqual(pendingBefore, tx.state) {
		t.Fatal("governance reads changed pending transaction state")
	}
	// Pure transition reads ignore even historical, over-budget reason bodies.
	v := tx.state.Waivers["tenant-waiver"]
	v.Reason = strings.Repeat("r", 65537)
	tx.state.Waivers[v.ID] = v
	e := tx.state.Exceptions["tenant-exception"]
	e.Reason = strings.Repeat("r", 65537)
	tx.state.Exceptions[e.ID] = e
	pendingBefore, err = cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := waivers.ReadWaiverTransitionState(t.Context(), "tenant", v.ID); err != nil || state.ScopeID != v.ScopeID || state.ExpiresAt != v.ExpiresAt || !state.Approved {
		t.Fatal("waiver authority read inspected unrelated reasons", err)
	}
	if state, err := exceptions.ReadExceptionTransitionState(t.Context(), "tenant", e.ID); err != nil || state.ReleaseID != e.ReleaseID || state.FindingID != e.FindingID || state.ControlID != e.ControlID || !state.Approved {
		t.Fatal("exception authority read inspected unrelated reasons", err)
	}
	if _, err := waivers.ReadWaiverForApproval(t.Context(), "tenant", v.ID); !errors.Is(err, ErrValidation) {
		t.Fatal("fresh waiver read accepted an over-budget reason", err)
	}
	if _, err := exceptions.ReadExceptionForApproval(t.Context(), "tenant", e.ID); !errors.Is(err, ErrValidation) {
		t.Fatal("fresh exception read accepted an over-budget reason", err)
	}
	if !reflect.DeepEqual(pendingBefore, tx.state) {
		t.Fatal("authority or rejected fresh-record reads changed pending state")
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("governance reads changed committed state", err)
	}
}

func TestMemoryGovernanceReadersRejectForeignMalformedCanceledAndClosedReads(t *testing.T) {
	_, tx := memoryGovernanceReadFixture(t)
	waivers := tx.Repositories().Governance.(riskapp.WaiverCommandReader)
	exceptions := tx.Repositories().Decisions.(riskapp.ExceptionCommandReader)
	approvals := tx.Repositories().Governance.(riskapp.ApprovalReader)
	checks := []struct {
		name, id string
		empty    any
		run      func(context.Context, string, string) (any, error)
	}{
		{"waiver-subject", "tenant-release", riskapp.GovernanceSubjectReference{}, func(ctx context.Context, tenant, id string) (any, error) {
			return waivers.ReadWaiverSubject(ctx, tenant, "release", id)
		}},
		{"waiver-transition", "tenant-waiver", riskapp.WaiverTransitionState{}, func(ctx context.Context, tenant, id string) (any, error) {
			return waivers.ReadWaiverTransitionState(ctx, tenant, id)
		}},
		{"waiver-record", "tenant-waiver", riskdomain.Waiver{}, func(ctx context.Context, tenant, id string) (any, error) {
			return waivers.ReadWaiverForApproval(ctx, tenant, id)
		}},
		{"exception-subject", "tenant-release", riskapp.GovernanceSubjectReference{}, func(ctx context.Context, tenant, id string) (any, error) {
			return exceptions.ReadExceptionSubject(ctx, tenant, "release", id)
		}},
		{"exception-transition", "tenant-exception", riskapp.ExceptionTransitionState{}, func(ctx context.Context, tenant, id string) (any, error) {
			return exceptions.ReadExceptionTransitionState(ctx, tenant, id)
		}},
		{"exception-record", "tenant-exception", riskdomain.Exception{}, func(ctx context.Context, tenant, id string) (any, error) {
			return exceptions.ReadExceptionForApproval(ctx, tenant, id)
		}},
		{"approval-subject", "tenant-release", riskapp.GovernanceSubjectReference{}, func(ctx context.Context, tenant, id string) (any, error) {
			return approvals.ReadApprovalSubject(ctx, tenant, "release", id)
		}},
		{"approval-evidence", "tenant-evidence", false, func(ctx context.Context, tenant, id string) (any, error) {
			return approvals.ApprovalEvidenceExists(ctx, tenant, id)
		}},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			for _, tenant := range []string{"foreign", "unknown"} {
				result, err := tc.run(t.Context(), tenant, tc.id)
				want := error(ErrNotFound)
				if tc.name == "approval-evidence" && tenant == "foreign" {
					want = nil
				}
				if !errors.Is(err, want) || !reflect.DeepEqual(result, tc.empty) {
					t.Fatal("foreign/missing tenant read exposed metadata", result, err)
				}
			}
			for _, bad := range []string{"", " ", " tenant ", "bad\x00", string([]byte{255}), strings.Repeat("x", 1025)} {
				for _, pair := range [][2]string{{bad, tc.id}, {"tenant", bad}} {
					result, err := tc.run(t.Context(), pair[0], pair[1])
					if !errors.Is(err, ErrValidation) || !reflect.DeepEqual(result, tc.empty) {
						t.Fatal("malformed coordinate read exposed metadata", result, err)
					}
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if result, err := tc.run(ctx, "tenant", tc.id); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, tc.empty) {
				t.Fatal("canceled read exposed metadata", result, err)
			}
		})
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range checks {
		if result, err := tc.run(t.Context(), "tenant", tc.id); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(result, tc.empty) {
			t.Fatal("closed read retained data access", tc.name, result, err)
		}
	}
}

func TestMemoryGovernanceCoordinatesRejectBrokenTypedParentsAndAmbiguousFindings(t *testing.T) {
	for _, tc := range []struct {
		name, kind, id string
		change         func(*MemoryUnitOfWorkSnapshot)
		want           error
	}{
		{"release-product", "release", "tenant-release", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Releases["tenant-release"]
			v.ProductID = "foreign-product"
			s.Releases[v.ID] = v
		}, ErrNotFound},
		{"control-framework", "control", "tenant-control", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.SecurityControls["tenant-control"]
			v.FrameworkID = "foreign-framework"
			s.SecurityControls[v.ID] = v
		}, ErrNotFound},
		{"scan-evidence", "finding", "tenant-finding", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["tenant-scan"]
			v.EvidenceID = "foreign-evidence"
			s.VulnerabilityScans[v.ID] = v
		}, ErrNotFound},
		{"scan-evidence-type", "finding", "tenant-finding", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-evidence"]
			v.Type = "manual"
			s.Evidence[v.ID] = v
		}, ErrNotFound},
		{"scan-evidence-invalid-project", "finding", "tenant-finding", func(s *MemoryUnitOfWorkSnapshot) {
			s.Projects["broken-project"] = domain.Project{ID: "broken-project", TenantID: "tenant"}
			v := s.Evidence["tenant-evidence"]
			v.ProductID, v.ProjectID = "", "broken-project"
			s.Evidence[v.ID] = v
		}, ErrNotFound},
		{"finding-duplicate", "finding", "tenant-finding", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["tenant-scan"]
			v.ID = "other-scan"
			s.VulnerabilityScans[v.ID] = v
		}, ErrConflict},
		{"finding-label", "finding", "tenant-finding", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["tenant-scan"]
			v.Findings[0].Vulnerability = " "
			s.VulnerabilityScans[v.ID] = v
		}, ErrValidation},
		{"waiver-scope", "waiver", "tenant-waiver", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Waivers["tenant-waiver"]
			v.ScopeID = "foreign-release"
			s.Waivers[v.ID] = v
		}, ErrNotFound},
		{"waiver-recursion", "waiver", "tenant-waiver", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Waivers["tenant-waiver"]
			v.ScopeType, v.ScopeID = "waiver", v.ID
			s.Waivers[v.ID] = v
		}, ErrNotFound},
		{"review-evidence", "security_review", "tenant-review", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.ManualSecurityDocuments["tenant-review"]
			v.EvidenceID = "foreign-review-evidence"
			s.ManualSecurityDocuments[v.ID] = v
		}, ErrNotFound},
		{"review-type", "security_review", "tenant-review", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.ManualSecurityDocuments["tenant-review"]
			v.DocumentType = "other"
			s.ManualSecurityDocuments[v.ID] = v
		}, ErrNotFound},
		{"diff-target", "contract_diff", "tenant-diff", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.ContractDiffs["tenant-diff"]
			v.TargetContractID = "foreign-contract-target"
			s.ContractDiffs[v.ID] = v
		}, ErrNotFound},
		{"contract-evidence", "contract_diff", "tenant-diff", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.OpenAPIContracts["tenant-contract-base"]
			v.EvidenceID = "foreign-contract-base-evidence"
			s.OpenAPIContracts[v.ID] = v
		}, ErrNotFound},
		{"package-redaction", "customer_package", "tenant-package", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.CustomerPackages["tenant-package"]
			v.RedactionProfileID = "foreign-redaction"
			s.CustomerPackages[v.ID] = v
		}, ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, tx := memoryGovernanceReadFixture(t)
			tc.change(&tx.state)
			reader := memoryGovernanceRepository{uow: tx}
			v, err := reader.readSubject(t.Context(), "tenant", tc.kind, tc.id)
			if !errors.Is(err, tc.want) || v != (riskapp.GovernanceSubjectReference{}) {
				t.Fatal("incoherent source returned usable governance authority", v, err)
			}
		})
	}
}
