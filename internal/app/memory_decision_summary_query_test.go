package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func memoryDecisionSummaryFixture(t *testing.T) (*memoryUnitOfWork, riskquery.DecisionSummaryReader, riskquery.DecisionSummaryRequest) {
	t.Helper()
	tx, _ := memoryReadinessQueryFixture(t)
	r, ok := tx.Repositories().Decisions.(riskquery.DecisionSummaryReader)
	if !ok {
		t.Fatal("memory Decision repository lacks native customer-summary reader")
	}
	now := fixedNow()
	d := domain.VulnerabilityDecision{ID: "decision", TenantID: "tenant", FindingID: "finding", ScanID: "scan", ReleaseID: "tenant-release", Vulnerability: "CVE-fixture", Component: "api", SBOMID: "sbom", SBOMComponentPURL: "pkg:generic/api@1", SBOMComponentName: "api", Status: "affected", Justification: "reviewed", ImpactStatement: "customer impact", ActionStatement: "patch planned", CustomerVisible: true, InternalNotes: "private triage", Source: "manual", EvidenceID: "source", EvidenceIDs: []string{"evidence"}, SupportingRefs: []domain.SubjectRef{{Type: "approval", ID: "approval", Digest: "digest"}}, VEXDocumentID: "vex", Supersedes: "old", ApprovedBy: "approver", ReviewedAt: &now, ReviewDueAt: &now, SchemaVersion: riskdomain.VulnerabilityDecisionVersion, CreatedAt: now}
	tx.state.Decisions = map[string]domain.VulnerabilityDecision{d.ID: d}
	return tx, r, riskquery.DecisionSummaryRequest{TenantID: "tenant", ReleaseID: "tenant-release", AllowedProductIDs: []string{"tenant-product"}}
}

func TestMemoryDecisionSummaryRejectsInvalidContextsParentsAndContainers(t *testing.T) {
	tx, reader, request := memoryDecisionSummaryFixture(t)
	var missing context.Context
	if _, err := reader.ReadVulnerabilityDecisionSummary(missing, request); !errors.Is(err, riskquery.ErrValidation) {
		t.Fatal("summary accepted nil context", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := reader.ReadVulnerabilityDecisionSummary(ctx, request); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, riskquery.DecisionSummarySnapshot{}) {
		t.Fatal("canceled summary returned data", err)
	}
	d := tx.state.Decisions["decision"]
	for _, malformed := range []string{"evidence", "supporting"} {
		bad := d
		if malformed == "evidence" {
			bad.EvidenceIDs = []string{"bad\x00id"}
		} else {
			bad.SupportingRefs = []domain.SubjectRef{{Type: "approval", ID: "\xff"}}
		}
		tx.state.Decisions[d.ID] = bad
		if value, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request); !errors.Is(err, riskquery.ErrInvalidProjection) || !reflect.DeepEqual(value, riskquery.DecisionSummarySnapshot{}) {
			t.Fatal("malformed selected container returned data", malformed, err)
		}
	}
	tx.state.Decisions[d.ID] = d
	p := tx.state.Products["tenant-product"]
	p.TenantID = "foreign"
	tx.state.Products[p.ID] = p
	if _, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request); !errors.Is(err, riskquery.ErrNotFound) {
		t.Fatal("summary accepted inconsistent release ownership", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request); !errors.Is(err, ErrConflict) {
		t.Fatal("summary read a closed transaction", err)
	}
}

func TestMemoryDecisionSummarySelectsCurrentPublicMetadataAndDetachedFields(t *testing.T) {
	tx, reader, request := memoryDecisionSummaryFixture(t)
	d := tx.state.Decisions["decision"]
	for _, kind := range []string{"hidden", "superseded", "foreign", "other-release"} {
		copy := d
		copy.ID, copy.Status, copy.ActionStatement = kind, "invalid", strings.Repeat("unselected", 1<<20)
		switch kind {
		case "hidden":
			copy.CustomerVisible = false
		case "superseded":
			copy.SupersededBy = d.ID
		case "foreign":
			copy.TenantID = "foreign"
		case "other-release":
			copy.ReleaseID = "other-release"
		}
		tx.state.Decisions[kind] = copy
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request)
	d.InternalNotes = ""
	want, conversionErr := domain.VulnerabilityDecisionToContextModel(d)
	if err != nil || conversionErr != nil || !reflect.DeepEqual(got, riskquery.DecisionSummarySnapshot{Release: riskquery.ReleaseScope{ID: "tenant-release", ProductID: "tenant-product"}, Decisions: []riskquery.DecisionPoint{{Decision: want, ProductID: "tenant-product"}}}) {
		t.Fatal("summary lost current public metadata or selected private/unrelated fields", err)
	}
	got.Decisions[0].Decision.EvidenceIDs[0] = "changed"
	got.Decisions[0].Decision.SupportingRefs[0].Digest = "changed"
	*got.Decisions[0].Decision.ReviewedAt = fixedNow().AddDate(1, 0, 0)
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("summary read or caller mutation changed repository state")
	}
	request.AllowedProductIDs = nil
	if value, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request); !errors.Is(err, application.ErrForbidden) || !reflect.DeepEqual(value, riskquery.DecisionSummarySnapshot{}) {
		t.Fatal("summary retained revoked resource grant", err)
	}
	request.TenantID = "foreign"
	if _, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request); !errors.Is(err, riskquery.ErrNotFound) {
		t.Fatal("summary disclosed foreign release", err)
	}
}

func TestMemoryDecisionSummaryBoundsSelectionAndAuthorizesBeforeMalformedContent(t *testing.T) {
	tx, reader, request := memoryDecisionSummaryFixture(t)
	d := tx.state.Decisions["decision"]
	d.InternalNotes = strings.Repeat("private", 2<<20)
	tx.state.Decisions[d.ID] = d
	for i := 1; i < riskquery.MaxDecisionSummaryDecisions; i++ {
		copy := d
		copy.ID = fmt.Sprintf("decision-%04d", i)
		tx.state.Decisions[copy.ID] = copy
	}
	got, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request)
	if err != nil || len(got.Decisions) != riskquery.MaxDecisionSummaryDecisions || got.Decisions[0].Decision.ID != "decision" || got.Decisions[len(got.Decisions)-1].Decision.ID != "decision-4095" {
		t.Fatal("summary truncated exact row limit or lost deterministic tie order", err)
	}
	copy := d
	copy.ID = "overflow"
	tx.state.Decisions[copy.ID] = copy
	if value, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request); !errors.Is(err, riskquery.ErrInvalidProjection) || !reflect.DeepEqual(value, riskquery.DecisionSummarySnapshot{}) {
		t.Fatal("summary overflow returned partial data", err)
	}
	tx.state.Decisions = map[string]domain.VulnerabilityDecision{d.ID: d}
	d.ActionStatement = strings.Repeat("large", 2<<20)
	tx.state.Decisions[d.ID] = d
	if _, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request); !errors.Is(err, riskquery.ErrInvalidProjection) {
		t.Fatal("summary returned excessive selected text", err)
	}
	d.Status = "invalid"
	tx.state.Decisions[d.ID] = d
	request.AllowedProductIDs = nil
	if _, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("summary inspected malformed content before authority", err)
	}
	request.AllowedProductIDs = []string{"tenant-product"}
	d.ActionStatement = "patch"
	tx.state.Decisions[d.ID] = d
	if _, err := reader.ReadVulnerabilityDecisionSummary(t.Context(), request); !errors.Is(err, riskquery.ErrInvalidProjection) {
		t.Fatal("selected malformed status did not fail closed", err)
	}
}
