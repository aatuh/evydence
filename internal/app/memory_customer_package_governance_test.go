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
)

func memoryCustomerGovernanceProfile() packagedomain.RedactionProfile {
	return packagedomain.RedactionProfile{ID: "profile", TenantID: "tenant", AllowedTypes: []string{"vulnerability_decision"}}
}

func timePtr(at time.Time) *time.Time { return &at }

func memoryCustomerGovernanceFixture(t *testing.T) *memoryUnitOfWork {
	t.Helper()
	tx := memoryCustomerEvidenceFixture(t)
	s := &tx.state
	for _, tenant := range []string{"tenant", "foreign"} {
		s.ControlFrameworks[tenant+"-framework"] = domain.ControlFramework{ID: tenant + "-framework", TenantID: tenant}
		s.SecurityControls[tenant+"-control"] = domain.SecurityControl{ID: tenant + "-control", TenantID: tenant, FrameworkID: tenant + "-framework", Objective: "private-control-marker"}
	}
	s.SecurityControls["broken-control"] = domain.SecurityControl{ID: "broken-control", TenantID: "tenant", FrameworkID: "foreign-framework"}
	s.CustomPolicies["policy"] = domain.CustomPolicy{ID: "policy", TenantID: "tenant"}
	s.CustomPolicies["foreign-policy"] = domain.CustomPolicy{ID: "foreign-policy", TenantID: "foreign"}
	scan := s.VulnerabilityScans["scan"]
	scan.Findings = []domain.VulnerabilityFinding{{ID: "finding", Vulnerability: "CVE-1", Component: "component", Severity: "critical"}}
	s.VulnerabilityScans[scan.ID] = scan
	for _, subject := range []struct{ id, kind, root, evidence string }{{"approval-product", "product", "tenant-product", ""}, {"approval-release", "release", "tenant-release", "selected"}, {"approval-sibling", "release", "sibling-release", ""}, {"approval-bad-evidence", "release", "tenant-release", "bad-project"}} {
		s.Approvals[subject.id] = domain.ApprovalRecord{ID: subject.id, TenantID: "tenant", SubjectType: subject.kind, SubjectID: subject.root, EvidenceID: subject.evidence, Decision: "approve", Reason: "reviewed", ApproverID: "private-approver-marker", CreatedAt: fixedNow()}
	}
	x := domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "tenant-release", FindingID: "finding", ControlID: "tenant-control", Reason: "reviewed", Owner: "security", Approved: true, ApprovedBy: "private-approver-marker", ApprovedAt: timePtr(fixedNow()), ExpiresAt: fixedNow().Add(time.Hour), CreatedAt: fixedNow()}
	s.Exceptions[x.ID] = x
	for _, id := range []string{"exception-expired", "exception-pending", "exception-bad-control", "exception-bad-finding"} {
		v := x
		v.ID = id
		switch id {
		case "exception-expired":
			v.ExpiresAt = fixedNow()
		case "exception-pending":
			v.Approved = false
		case "exception-bad-control":
			v.ControlID = "broken-control"
		case "exception-bad-finding":
			v.FindingID = "missing"
		}
		v.Reason = "private-omitted-marker"
		s.Exceptions[id] = v
	}
	w := domain.Waiver{ID: "waiver-release", TenantID: "tenant", ScopeType: "release", ScopeID: "tenant-release", ControlID: "tenant-control", PolicyID: "policy", Owner: "security", Risk: "accepted", Reason: "reviewed", Approved: true, ApprovedBy: "private-approver-marker", ApprovedAt: timePtr(fixedNow()), ExpiresAt: fixedNow().Add(time.Hour), CreatedAt: fixedNow()}
	s.Waivers[w.ID] = w
	for _, id := range []string{"waiver-product", "waiver-expired", "waiver-pending", "waiver-bad-policy", "waiver-bad-control", "waiver-other-kind"} {
		v := w
		v.ID = id
		switch id {
		case "waiver-product":
			v.ScopeType, v.ScopeID, v.ApprovedAt = "product", "tenant-product", nil
		case "waiver-expired":
			v.ExpiresAt = fixedNow()
		case "waiver-pending":
			v.Approved = false
		case "waiver-bad-policy":
			v.PolicyID = "foreign-policy"
		case "waiver-bad-control":
			v.ControlID = "broken-control"
		case "waiver-other-kind":
			v.ScopeType, v.ScopeID = "control", "tenant-control"
		}
		if id != "waiver-product" {
			v.Reason = "private-omitted-marker"
		}
		s.Waivers[id] = v
	}
	for _, row := range []struct{ id, product, release string }{{"answer-global", "", ""}, {"answer-product", "tenant-product", ""}, {"answer-release", "tenant-product", "tenant-release"}, {"answer-sibling", "sibling", ""}} {
		a := domain.QuestionnaireAnswerLibraryEntry{ID: row.id, TenantID: "tenant", QuestionID: "Q", ProductID: row.product, ReleaseID: row.release, Answer: "reviewed", CreatedAt: fixedNow()}
		if row.id == "answer-release" {
			a.EvidenceIDs, a.Limitations = []string{"selected"}, []string{"human review required"}
		}
		if row.id == "answer-sibling" {
			a.Answer = "private-omitted-marker"
		}
		s.AnswerLibrary[a.ID] = a
	}
	s.ReleaseBundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "tenant-release"}
	s.Incidents["incident"] = domain.Incident{ID: "incident", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Title: "private-incident-marker"}
	s.RemediationTasks["task"] = domain.RemediationTask{ID: "task", TenantID: "tenant", IncidentID: "incident", EvidenceID: "selected", Title: "private-task-marker"}
	d := domain.VulnerabilityDecision{ID: "decision", TenantID: "tenant", FindingID: "finding", ScanID: "scan", ReleaseID: "tenant-release", Vulnerability: "CVE-1", Component: "component", SBOMID: "sbom", SBOMComponentPURL: "pkg:example", SBOMComponentName: "component", Status: "fixed", Justification: "reviewed", ImpactStatement: "impact", ActionStatement: "upgrade", Source: "manual", CustomerVisible: true, EvidenceID: "selected", EvidenceIDs: []string{"selected"}, VEXDocumentID: "vex", ReviewedAt: timePtr(fixedNow()), ReviewDueAt: timePtr(fixedNow().Add(2 * time.Hour)), CreatedAt: fixedNow(), InternalNotes: "private-notes-marker", ApprovedBy: "private-reviewer-marker"}
	for _, ref := range []struct{ kind, id string }{{"approval", "approval-release"}, {"exception", "exception"}, {"waiver", "waiver-release"}, {"release_bundle", "bundle"}, {"incident", "incident"}, {"remediation_task", "task"}} {
		d.SupportingRefs = append(d.SupportingRefs, domain.SubjectRef{Type: ref.kind, ID: ref.id, Digest: "sha256:" + ref.id})
	}
	s.Decisions[d.ID] = d
	d.ID, d.CustomerVisible, d.Justification = "hidden-decision", false, "private-hidden-marker"
	s.Decisions[d.ID] = d
	// Foreign rows deliberately reuse this product/release's coordinates.
	a := s.Approvals["approval-release"]
	a.ID, a.TenantID, a.Reason = "foreign-approval", "foreign", "private-foreign-marker"
	s.Approvals[a.ID] = a
	x.ID, x.TenantID, x.Reason = "foreign-exception", "foreign", "private-foreign-marker"
	s.Exceptions[x.ID] = x
	w.ID, w.TenantID, w.Reason = "foreign-waiver", "foreign", "private-foreign-marker"
	s.Waivers[w.ID] = w
	answer := s.AnswerLibrary["answer-release"]
	answer.ID, answer.TenantID, answer.Answer = "foreign-answer", "foreign", "private-foreign-marker"
	s.AnswerLibrary[answer.ID] = answer
	d.ID, d.TenantID, d.CustomerVisible, d.Justification = "foreign-decision", "foreign", true, "private-foreign-marker"
	s.Decisions[d.ID] = d
	return tx
}

func TestMemoryCustomerPackageGovernanceRechecksExtendedApprovalSubjects(t *testing.T) {
	for _, kind := range []string{"waiver", "customer_package", "contract_diff", "security_review"} {
		t.Run(kind, func(t *testing.T) {
			tx := memoryCustomerGovernanceFixture(t)
			s := &tx.state
			s.RedactionProfiles["policy-profile"] = domain.RedactionProfile{ID: "policy-profile", TenantID: "tenant"}
			s.CustomerPackages["customer"] = domain.CustomerSecurityPackage{ID: "customer", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", RedactionProfileID: "policy-profile"}
			e := s.Evidence["selected"]
			e.ID, e.Type = "review-source", "security_review"
			s.Evidence[e.ID] = e
			s.ManualSecurityDocuments["review"] = domain.ManualSecurityDocument{ID: "review", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", DocumentType: "security_review", EvidenceID: e.ID}
			id := map[string]string{"waiver": "waiver-release", "customer_package": "customer", "contract_diff": "diff", "security_review": "review"}[kind]
			a := s.Approvals["approval-release"]
			a.ID, a.SubjectType, a.SubjectID = "extended-approval", kind, id
			s.Approvals[a.ID] = a
			d := s.Decisions["decision"]
			d.SupportingRefs = []domain.SubjectRef{{Type: "approval", ID: a.ID}}
			s.Decisions[d.ID] = d
			read := func() memoryCustomerPackageGovernance {
				v, err := readMemoryCustomerPackageGovernance(t.Context(), s, "tenant", "tenant-product", "tenant-release", memoryCustomerGovernanceProfile(), fixedNow(), &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			if len(read().Decisions) != 1 {
				t.Fatal("owned extended approval was not accepted", kind)
			}
			switch kind {
			case "waiver":
				w := s.Waivers[id]
				w.PolicyID = "foreign-policy"
				s.Waivers[id] = w
			case "customer_package":
				p := s.RedactionProfiles["policy-profile"]
				p.TenantID = "foreign"
				s.RedactionProfiles[p.ID] = p
			case "contract_diff":
				c := s.OpenAPIContracts["base-contract"]
				c.ProductID = "sibling"
				s.OpenAPIContracts[c.ID] = c
			case "security_review":
				e.ProjectID = "sibling-project"
				s.Evidence[e.ID] = e
			}
			if len(read().Decisions) != 0 {
				t.Fatal("foreign/incoherent extended approval authority retained", kind)
			}
		})
	}
}

func TestMemoryCustomerPackageGovernanceValidatesRootsTimeAndSharedBudget(t *testing.T) {
	tx := memoryCustomerGovernanceFixture(t)
	for _, coordinates := range [][3]string{{"tenant", "foreign-product", ""}, {"foreign", "tenant-product", "tenant-release"}, {"tenant", "tenant-product", "sibling-release"}, {"unknown", "tenant-product", ""}} {
		p := memoryCustomerGovernanceProfile()
		p.TenantID = coordinates[0]
		v, err := readMemoryCustomerPackageGovernance(t.Context(), &tx.state, coordinates[0], coordinates[1], coordinates[2], p, fixedNow(), &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
		if !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, memoryCustomerPackageGovernance{}) {
			t.Fatal("foreign roots returned governance data", coordinates, err)
		}
	}
	for _, at := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("fixture", 3600))} {
		if v, err := readMemoryCustomerPackageGovernance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerGovernanceProfile(), at, &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, ErrValidation) || !reflect.DeepEqual(v, memoryCustomerPackageGovernance{}) {
			t.Fatal("invalid generation time accepted", err)
		}
	}
	baseline := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readMemoryCustomerPackageGovernance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerGovernanceProfile(), fixedNow(), baseline); err != nil {
		t.Fatal(err)
	}
	used := packageapp.MaxCustomerPackageManifestBytes - baseline.remainingBytes
	b := &memoryCustomerSnapshotBudget{remainingBytes: used - 1}
	if v, err := readMemoryCustomerPackageGovernance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerGovernanceProfile(), fixedNow(), b); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, memoryCustomerPackageGovernance{}) || b.remainingBytes != used-1 {
		t.Fatal("section budgets reset or published partial consumption", err)
	}
}

func TestMemoryCustomerPackageGovernancePreservesOwnedPublicSectionsAndProfileExclusions(t *testing.T) {
	tx := memoryCustomerGovernanceFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	read := func(release string, profile packagedomain.RedactionProfile) (memoryCustomerPackageGovernance, error) {
		return readMemoryCustomerPackageGovernance(t.Context(), &tx.state, "tenant", "tenant-product", release, profile, fixedNow(), &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	}
	v, err := read("tenant-release", memoryCustomerGovernanceProfile())
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []struct {
		rows []map[string]any
		ids  string
	}{{v.Decisions, "decision"}, {v.Approvals, "approval-product,approval-release"}, {v.Exceptions, "exception"}, {v.Waivers, "waiver-product,waiver-release"}, {v.AnswerLibrary, "answer-global,answer-product,answer-release"}} {
		var ids []string
		for _, row := range part.rows {
			ids = append(ids, row["id"].(string))
		}
		if strings.Join(ids, ",") != part.ids {
			t.Fatal("governance scope changed", ids, part.ids)
		}
	}
	if v.Decisions[0]["reviewed_at"] != fixedNow().UTC().Format(time.RFC3339) || v.Exceptions[0]["approved_at"] != fixedNow().UTC().Format(time.RFC3339) || !reflect.DeepEqual(v.AnswerLibrary[2]["evidence_ids"], []string{"selected"}) || !reflect.DeepEqual(v.AnswerLibrary[2]["limitations"], []string{"human review required"}) || len(v.Decisions[0]["supporting_refs"].([]map[string]any)) != 6 {
		t.Fatal("public governance shapes changed", v)
	}
	if _, present := v.Waivers[0]["approved_at"]; present {
		t.Fatal("absent timestamp was not omitted")
	}
	raw, err := json.Marshal(v)
	if err != nil || strings.Contains(string(raw), "private-") {
		t.Fatal("private governance metadata projected", err)
	}
	v.Decisions[0]["evidence_ids"].([]string)[0] = "changed"
	v.Decisions[0]["supporting_refs"].([]map[string]any)[0]["digest"] = "changed"
	v.AnswerLibrary[2]["evidence_ids"].([]string)[0] = "changed"
	v.AnswerLibrary[2]["limitations"].([]string)[0] = "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("read/caller mutation changed repository rows")
	}
	profile := memoryCustomerGovernanceProfile()
	profile.ExcludedFields = []string{"justification", "reviewed_at", "evidence_ids", "supporting_refs"}
	redacted, err := read("tenant-release", profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range profile.ExcludedFields {
		if _, present := redacted.Decisions[0][field]; present {
			t.Fatal("decision exclusion ignored", field)
		}
	}
	product, err := read("", memoryCustomerGovernanceProfile())
	if err != nil || len(product.Decisions) != 0 || len(product.Exceptions) != 0 || len(product.Approvals) != 1 || len(product.Waivers) != 1 || len(product.AnswerLibrary) != 2 {
		t.Fatal("product-only governance scope changed", product, err)
	}
}

func TestMemoryCustomerPackageGovernanceRejectsForeignReferencesAndInvalidSelectedMetadata(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*MemoryUnitOfWorkSnapshot)
	}{
		{"scan source", func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["vulnerability_scan-source"]
			e.ProjectID = "sibling-project"
			s.Evidence[e.ID] = e
		}},
		{"finding tuple", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.Decisions["decision"]
			d.Component = "different"
			s.Decisions[d.ID] = d
		}},
		{"duplicate finding", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.VulnerabilityScans["scan"]
			d.Findings = append(d.Findings, d.Findings[0])
			s.VulnerabilityScans[d.ID] = d
		}},
		{"citation", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.Decisions["decision"]
			d.EvidenceIDs = []string{"bad-project"}
			s.Decisions[d.ID] = d
		}},
		{"superseded", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.Decisions["decision"]
			d.SupersededBy = "new"
			s.Decisions[d.ID] = d
		}},
		{"sbom binding", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.SBOMs["sbom"]
			d.ArtifactID = "artifact-foreign"
			s.SBOMs[d.ID] = d
		}},
		{"support tenant", func(s *MemoryUnitOfWorkSnapshot) {
			a := s.Approvals["approval-release"]
			a.TenantID = "foreign"
			s.Approvals[a.ID] = a
		}},
		{"support incident", func(s *MemoryUnitOfWorkSnapshot) {
			i := s.Incidents["incident"]
			i.ProductID = "sibling"
			s.Incidents[i.ID] = i
		}},
		{"support task", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.RemediationTasks["task"]
			v.EvidenceID = "bad-project"
			s.RemediationTasks[v.ID] = v
		}},
		{"support kind", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.Decisions["decision"]
			d.SupportingRefs = []domain.SubjectRef{{Type: "product", ID: "tenant-product"}}
			s.Decisions[d.ID] = d
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerGovernanceFixture(t)
			change.edit(&tx.state)
			v, err := readMemoryCustomerPackageGovernance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerGovernanceProfile(), fixedNow(), &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v.Decisions) != 0 {
				t.Fatal("unowned/incoherent decision projected", v.Decisions, err)
			}
		})
	}
	for _, change := range []struct {
		name string
		edit func(*MemoryUnitOfWorkSnapshot)
	}{
		{"citation count", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.Decisions["decision"]
			d.EvidenceIDs = make([]string, 4097)
			s.Decisions[d.ID] = d
		}},
		{"support count", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.Decisions["decision"]
			d.SupportingRefs = make([]domain.SubjectRef, 4097)
			s.Decisions[d.ID] = d
		}},
		{"answer length", func(s *MemoryUnitOfWorkSnapshot) {
			a := s.AnswerLibrary["answer-release"]
			a.Answer = strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)
			s.AnswerLibrary[a.ID] = a
		}},
		{"limitation count", func(s *MemoryUnitOfWorkSnapshot) {
			a := s.AnswerLibrary["answer-release"]
			a.Limitations = make([]string, 4097)
			s.AnswerLibrary[a.ID] = a
		}},
		{"timestamp range", func(s *MemoryUnitOfWorkSnapshot) {
			x := s.Exceptions["exception"]
			x.ApprovedAt = timePtr(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
			s.Exceptions[x.ID] = x
		}},
		{"excluded public length", func(s *MemoryUnitOfWorkSnapshot) {
			d := s.Decisions["decision"]
			d.Justification = strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)
			s.Decisions[d.ID] = d
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerGovernanceFixture(t)
			change.edit(&tx.state)
			b := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			p := memoryCustomerGovernanceProfile()
			p.ExcludedFields = []string{"justification"}
			v, err := readMemoryCustomerPackageGovernance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", p, fixedNow(), b)
			if !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, memoryCustomerPackageGovernance{}) || b.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
				t.Fatal("partial invalid governance result/budget", err)
			}
		})
	}
	tx := memoryCustomerGovernanceFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readMemoryCustomerPackageGovernance(ctx, &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerGovernanceProfile(), fixedNow(), &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, memoryCustomerPackageGovernance{}) {
		t.Fatal("cancelled governance returned", err)
	}
}
