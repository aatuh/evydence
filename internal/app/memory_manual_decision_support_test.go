package app

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func memoryManualDecisionSupportFixture(t *testing.T) (*memoryUnitOfWork, riskapp.VulnerabilityDecisionReader) {
	t.Helper()
	tx, reader := memoryManualDecisionReadFixture(t)
	tx.state.Exceptions["exception"] = domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "tenant-release"}
	tx.state.Waivers["waiver"] = domain.Waiver{ID: "waiver", TenantID: "tenant", ScopeType: "release", ScopeID: "tenant-release"}
	tx.state.Incidents["incident"] = domain.Incident{ID: "incident", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release"}
	tx.state.RemediationTasks["task"] = domain.RemediationTask{ID: "task", TenantID: "tenant", IncidentID: "incident", ReleaseID: "tenant-release", EvidenceID: "sbom-source"}
	tx.state.ReleaseBundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "tenant-release"}
	tx.state.Approvals["approval"] = domain.ApprovalRecord{ID: "approval", TenantID: "tenant", SubjectType: "release", SubjectID: "tenant-release", EvidenceID: "sbom-source"}
	return tx, reader
}

func TestMemoryManualDecisionSupportRequiresExactCurrentProductReleaseAndParents(t *testing.T) {
	tx, reader := memoryManualDecisionSupportFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []riskdomain.SupportingReference{{Type: "exception", ID: "exception"}, {Type: "waiver", ID: "waiver"}, {Type: "incident", ID: "incident"}, {Type: "remediation_task", ID: "task"}, {Type: "release_bundle", ID: "bundle"}, {Type: "approval", ID: "approval"}} {
		if err := reader.ValidateDecisionSupportingReference(t.Context(), "tenant", "tenant-product", "tenant-release", ref); err != nil {
			t.Fatal("manual support rejected owned current reference", ref.Type, err)
		}
		if err := reader.ValidateDecisionSupportingReference(t.Context(), "foreign", "tenant-product", "tenant-release", ref); !errors.Is(err, ErrNotFound) {
			t.Fatal("manual support accepted a foreign record", ref.Type, err)
		}
		ref.Digest = "sha256:caller-assertion"
		if err := reader.ValidateDecisionSupportingReference(t.Context(), "tenant", "tenant-product", "tenant-release", ref); !errors.Is(err, ErrValidation) {
			t.Fatal("manual support accepted unsupported digest assertion", ref.Type, err)
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("manual support checks changed repository data")
	}
	if err := reader.ValidateDecisionSupportingReference(t.Context(), "tenant", "tenant-product", "tenant-release", riskdomain.SupportingReference{Type: "evidence", ID: "sbom-source"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("manual support accepted an unsupported kind", err)
	}
	task := tx.state.RemediationTasks["task"]
	for _, field := range []string{"incident", "release", "evidence"} {
		bad := task
		switch field {
		case "incident":
			bad.IncidentID = "missing"
		case "release":
			bad.ReleaseID = "another-release"
		case "evidence":
			bad.EvidenceID = "missing"
		}
		tx.state.RemediationTasks[bad.ID] = bad
		if err := reader.ValidateDecisionSupportingReference(t.Context(), "tenant", "tenant-product", "tenant-release", riskdomain.SupportingReference{Type: "remediation_task", ID: "task"}); !errors.Is(err, ErrNotFound) {
			t.Fatal("manual task support accepted inconsistent supplied parent", field, err)
		}
	}
	tx.state.RemediationTasks[task.ID] = task
	i := tx.state.Incidents["incident"]
	i.ProductID = "another-product"
	tx.state.Incidents[i.ID] = i
	if err := reader.ValidateDecisionSupportingReference(t.Context(), "tenant", "tenant-product", "tenant-release", riskdomain.SupportingReference{Type: "remediation_task", ID: "task"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("manual task's direct release bypassed wrong incident product", err)
	}
}

func TestMemoryManualDecisionApprovalSupportValidatesEachClosedSubjectShape(t *testing.T) {
	tx, reader := memoryManualDecisionSupportFixture(t)
	tx.state.RedactionProfiles["profile"] = domain.RedactionProfile{ID: "profile", TenantID: "tenant"}
	tx.state.CustomerPackages["package"] = domain.CustomerSecurityPackage{ID: "package", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", RedactionProfileID: "profile"}
	tx.state.Evidence["review-source"] = domain.EvidenceItem{ID: "review-source", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Type: "security_review"}
	tx.state.ManualSecurityDocuments["review"] = domain.ManualSecurityDocument{ID: "review", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", DocumentType: "security_review", EvidenceID: "review-source"}
	tx.state.ContractDiffs["diff"] = domain.ContractDiff{ID: "diff", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", BaseContractID: "contract", TargetContractID: "contract"}
	a := tx.state.Approvals["approval"]
	for _, subject := range [][2]string{{"release", "tenant-release"}, {"waiver", "waiver"}, {"customer_package", "package"}, {"security_review", "review"}, {"contract_diff", "diff"}} {
		a.SubjectType, a.SubjectID = subject[0], subject[1]
		tx.state.Approvals[a.ID] = a
		if err := reader.ValidateDecisionSupportingReference(t.Context(), "tenant", "tenant-product", "tenant-release", riskdomain.SupportingReference{Type: "approval", ID: a.ID}); err != nil {
			t.Fatal("manual approval support rejected native subject shape", subject, err)
		}
		a.SubjectID = "missing"
		tx.state.Approvals[a.ID] = a
		if err := reader.ValidateDecisionSupportingReference(t.Context(), "tenant", "tenant-product", "tenant-release", riskdomain.SupportingReference{Type: "approval", ID: a.ID}); !errors.Is(err, ErrNotFound) {
			t.Fatal("manual approval support accepted missing native subject", subject, err)
		}
	}
	a.SubjectType, a.SubjectID = "product", "tenant-product"
	tx.state.Approvals[a.ID] = a
	if err := reader.ValidateDecisionSupportingReference(t.Context(), "tenant", "tenant-product", "tenant-release", riskdomain.SupportingReference{Type: "approval", ID: a.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatal("manual approval support accepted unsupported subject", err)
	}
}
