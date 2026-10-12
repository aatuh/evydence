package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func memoryVEXPointFixture(t *testing.T) (*memoryUnitOfWork, evidencequery.VEXPointReader, *evidencequery.VEXPoints, domain.Actor) {
	t.Helper()
	tx, _ := memoryParsedPointFixture(t)
	reader, ok := tx.Repositories().Evidence.(evidencequery.VEXPointReader)
	if !ok {
		t.Fatal("memory Evidence repository lacks native VEX document/report points")
	}
	query, err := evidencequery.NewVEXPoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	e := tx.state.Evidence["sbom-source"]
	e.ID, e.Type = "vex-source", "vex"
	tx.state.Evidence[e.ID] = e
	tx.state.VEXDocuments = map[string]domain.VEXDocument{"vex": {ID: "vex", TenantID: "tenant", EvidenceID: e.ID, ReleaseID: "tenant-release", ArtifactID: "artifact", Format: "openvex", Author: "security@example.test", Version: "1", StatementCount: 2, StatusSummary: map[string]int{"fixed": 1, "not_affected": 1}, SchemaVersion: "vex-document.v1", CreatedAt: fixedNow()}}
	tx.state.VEXImportReports = map[string]domain.VEXImportReport{"report": {ID: "report", TenantID: "tenant", VEXDocumentID: "vex", EvidenceID: e.ID, ReleaseID: "tenant-release", ArtifactID: "artifact", ParserVersion: "openvex.v1", Status: "failed", StatementCount: 2, DecisionsCreated: 1, DecisionsSuperseded: 1, UnsupportedFields: []string{"extra"}, Warnings: []string{"review limitation"}, InvalidStatements: []domain.VEXImportIssue{{StatementIndex: 2, Code: "invalid", Detail: "Unsupported value."}}, MappingFailures: []domain.VEXImportIssue{{StatementIndex: 1, Code: "unmatched", Detail: "No match."}}, FailureCode: "mapping_failed", FailureDetail: "Mapping failed.", SchemaVersion: "vex-report.v1", CreatedAt: fixedNow(), UpdatedAt: fixedNow().Add(time.Minute)}}
	actor := domain.Actor{TenantID: "tenant", UserID: "reader", Scopes: []string{ScopeEvidenceRead}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "tenant-product", Scopes: []string{ScopeEvidenceRead}}}}
	return tx, reader, query, actor
}

func TestMemoryVEXPointsReturnCompleteDetachedCurrentMetadata(t *testing.T) {
	tx, reader, query, actor := memoryVEXPointFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	wantDoc := evidencequery.VEXDocumentPoint{ProductID: "tenant-product", Document: evidencedomain.VEXDocument{ID: "vex", TenantID: "tenant", EvidenceID: "vex-source", ReleaseID: "tenant-release", ArtifactID: "artifact", Format: "openvex", Author: "security@example.test", Version: "1", StatementCount: 2, StatusSummary: map[string]int{"fixed": 1, "not_affected": 1}, SchemaVersion: "vex-document.v1", CreatedAt: fixedNow()}}
	point, err := reader.GetVEXDocumentPoint(t.Context(), "tenant", " vex ")
	if err != nil || !reflect.DeepEqual(point, wantDoc) {
		t.Fatal("VEX point lost current coordinates or recorded metadata", point, err)
	}
	wantReport := evidencedomain.VEXImportReport{ID: "report", TenantID: "tenant", VEXDocumentID: "vex", EvidenceID: "vex-source", ReleaseID: "tenant-release", ArtifactID: "artifact", ParserVersion: "openvex.v1", Status: "failed", StatementCount: 2, DecisionsCreated: 1, DecisionsSuperseded: 1, UnsupportedFields: []string{"extra"}, Warnings: []string{"review limitation"}, InvalidStatements: []evidencedomain.VEXImportIssue{{StatementIndex: 2, Code: "invalid", Detail: "Unsupported value."}}, MappingFailures: []evidencedomain.VEXImportIssue{{StatementIndex: 1, Code: "unmatched", Detail: "No match."}}, FailureCode: "mapping_failed", FailureDetail: "Mapping failed.", SchemaVersion: "vex-report.v1", CreatedAt: fixedNow(), UpdatedAt: fixedNow().Add(time.Minute)}
	report, err := reader.GetVEXImportReportPoint(t.Context(), "tenant", "vex")
	if err != nil || !reflect.DeepEqual(report, evidencequery.VEXImportReportPoint{Document: wantDoc, Report: wantReport}) {
		t.Fatal("VEX report point lost complete metadata or document binding", report, err)
	}
	point.Document.StatusSummary["fixed"] = -1
	report.Document.Document.StatusSummary["fixed"] = -2
	report.Report.Warnings[0], report.Report.UnsupportedFields[0] = "changed", "changed"
	report.Report.InvalidStatements[0].Detail, report.Report.MappingFailures[0].Detail = "changed", "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("VEX reads or caller mutation changed current rows")
	}
	actor.ResourceGrants = nil
	if _, err := query.GetVEXDocument(t.Context(), actor, "vex"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("VEX point retained revoked grant", err)
	}
	if _, err := query.GetVEXImportReport(t.Context(), actor, "vex"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("VEX report retained revoked grant", err)
	}
}

func TestMemoryVEXPointsRejectForeignAndIncoherentSources(t *testing.T) {
	for _, change := range []string{"foreign-root", "root-id-mismatch", "foreign-source", "source-id-mismatch", "missing-source", "wrong-kind", "wrong-release", "foreign-product", "missing-product", "missing-release", "missing-build", "foreign-artifact", "missing-artifact", "ambiguous-artifact", "missing-artifact-ref", "undeclared-artifact"} {
		t.Run(change, func(t *testing.T) {
			tx, reader, _, _ := memoryVEXPointFixture(t)
			d, e := tx.state.VEXDocuments["vex"], tx.state.Evidence["vex-source"]
			switch change {
			case "foreign-root":
				d.TenantID = "foreign"
			case "root-id-mismatch":
				d.ID = "another"
			case "foreign-source":
				e.TenantID = "foreign"
			case "source-id-mismatch":
				e.ID = "another"
			case "missing-source":
				d.EvidenceID = "missing"
			case "wrong-kind":
				e.Type = "manual"
			case "wrong-release":
				e.ReleaseID = "foreign-release"
			case "foreign-product":
				e.ProductID = "foreign-product"
			case "missing-product":
				delete(tx.state.Products, "tenant-product")
			case "missing-release":
				delete(tx.state.Releases, "tenant-release")
			case "missing-build":
				e.BuildID = "missing"
			case "foreign-artifact":
				a := tx.state.Artifacts["artifact"]
				a.TenantID = "foreign"
				tx.state.Artifacts[a.ID] = a
			case "missing-artifact":
				delete(tx.state.Artifacts, "artifact")
			case "ambiguous-artifact":
				e.SubjectRefs = append(e.SubjectRefs, domain.SubjectRef{Type: "artifact", ID: "another"})
			case "missing-artifact-ref":
				e.SubjectRefs = nil
			case "undeclared-artifact":
				d.ArtifactID = ""
			}
			tx.state.VEXDocuments["vex"], tx.state.Evidence["vex-source"] = d, e
			if point, err := reader.GetVEXDocumentPoint(t.Context(), "tenant", "vex"); !errors.Is(err, evidencequery.ErrNotFound) || !reflect.DeepEqual(point, evidencequery.VEXDocumentPoint{}) {
				t.Fatal("incoherent source exposed document", point, err)
			}
			if point, err := reader.GetVEXImportReportPoint(t.Context(), "tenant", "vex"); !errors.Is(err, evidencequery.ErrNotFound) || !reflect.DeepEqual(point, evidencequery.VEXImportReportPoint{}) {
				t.Fatal("incoherent source exposed report", point, err)
			}
		})
	}
}

func TestMemoryVEXReportsRejectDuplicateLinkageAndNormalizeOnlyCompletedTime(t *testing.T) {
	tx, reader, query, actor := memoryVEXPointFixture(t)
	for _, change := range []string{"duplicate", "wrong-source", "wrong-release", "wrong-artifact"} {
		original := tx.state.VEXImportReports["report"]
		r := original
		switch change {
		case "duplicate":
			r.ID = "another-report"
		case "wrong-source":
			r.EvidenceID = "sbom-source"
		case "wrong-release":
			r.ReleaseID = "foreign-release"
		case "wrong-artifact":
			r.ArtifactID = "another"
		}
		tx.state.VEXImportReports[r.ID] = r
		if point, err := query.GetVEXImportReport(t.Context(), actor, "vex"); !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(point, evidencedomain.VEXImportReport{}) {
			t.Fatal("invalid report binding returned data", change, point, err)
		}
		delete(tx.state.VEXImportReports, r.ID)
		tx.state.VEXImportReports[original.ID] = original
	}
	r := tx.state.VEXImportReports["report"]
	r.UpdatedAt = r.CreatedAt.Add(-time.Second)
	tx.state.VEXImportReports[r.ID] = r
	point, err := reader.GetVEXImportReportPoint(t.Context(), "tenant", "vex")
	if err != nil || !point.Report.UpdatedAt.Equal(r.CreatedAt) || !tx.state.VEXImportReports[r.ID].UpdatedAt.Equal(r.UpdatedAt) {
		t.Fatal("completed time normalization mutated history or lost recovery", point, err)
	}
	r.Status = "accepted"
	tx.state.VEXImportReports[r.ID] = r
	if _, err := query.GetVEXImportReport(t.Context(), actor, "vex"); !errors.Is(err, evidencequery.ErrConflict) {
		t.Fatal("accepted report received completed-time normalization", err)
	}
	delete(tx.state.VEXImportReports, r.ID)
	if _, err := reader.GetVEXImportReportPoint(t.Context(), "tenant", "vex"); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatal("missing report accepted", err)
	}
	var absent context.Context
	if _, err := reader.GetVEXDocumentPoint(absent, "tenant", "vex"); !errors.Is(err, evidencequery.ErrValidation) {
		t.Fatal("nil VEX context accepted", err)
	}
	base, cancel := context.WithCancel(t.Context())
	cancel()
	if point, err := reader.GetVEXDocumentPoint(base, "tenant", "vex"); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(point, evidencequery.VEXDocumentPoint{}) {
		t.Fatal("canceled VEX read returned data", point, err)
	}
	if _, err := reader.GetVEXDocumentPoint(t.Context(), "tenant", "vex"); err != nil {
		t.Fatal("canceled VEX read retained lock", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.GetVEXDocumentPoint(t.Context(), "tenant", "vex"); !errors.Is(err, ErrConflict) {
		t.Fatal("closed VEX transaction accepted", err)
	}
}

func TestMemoryVEXPointsBoundSelectedJSON(t *testing.T) {
	const limit = 16 << 20
	if !memoryVEXJSONFits(strings.Repeat("x", limit-2)) || memoryVEXJSONFits(strings.Repeat("x", limit-1)) {
		t.Fatal("VEX JSON budget lost the exact byte boundary")
	}
	for _, field := range []string{"summary", "warnings", "invalid", "failures"} {
		t.Run(field, func(t *testing.T) {
			tx, reader, _, _ := memoryVEXPointFixture(t)
			r := tx.state.VEXImportReports["report"]
			long := strings.Repeat("x", limit)
			switch field {
			case "summary":
				d := tx.state.VEXDocuments["vex"]
				d.StatusSummary = map[string]int{long: 1}
				tx.state.VEXDocuments[d.ID] = d
				if value, err := reader.GetVEXDocumentPoint(t.Context(), "tenant", d.ID); !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(value, evidencequery.VEXDocumentPoint{}) {
					t.Fatal("oversized document summary returned partial data", err)
				}
			case "warnings":
				r.Warnings = []string{long}
			case "invalid":
				r.InvalidStatements[0].Detail = long
			case "failures":
				r.MappingFailures[0].Detail = long
			}
			tx.state.VEXImportReports[r.ID] = r
			if value, err := reader.GetVEXImportReportPoint(t.Context(), "tenant", "vex"); !errors.Is(err, evidencequery.ErrConflict) || !reflect.DeepEqual(value, evidencequery.VEXImportReportPoint{}) {
				t.Fatal("oversized selected report JSON returned partial data", err)
			}
		})
	}
	tx, reader, _, _ := memoryVEXPointFixture(t)
	r := tx.state.VEXImportReports["report"]
	r.Warnings = []string{strings.Repeat("x", limit-4)}
	tx.state.VEXImportReports[r.ID] = r
	if point, err := reader.GetVEXImportReportPoint(t.Context(), "tenant", "vex"); err != nil || len(point.Report.Warnings[0]) != limit-4 {
		t.Fatal("exactly bounded JSON was rejected or truncated", err)
	}
}

func TestMemoryVEXPointsPreserveReleaseLessProductAuthorityAndNullableCollections(t *testing.T) {
	tx, reader, query, actor := memoryVEXPointFixture(t)
	d, e, r := tx.state.VEXDocuments["vex"], tx.state.Evidence["vex-source"], tx.state.VEXImportReports["report"]
	d.ReleaseID, d.ArtifactID, e.ReleaseID, r.ReleaseID, r.ArtifactID = "", "", "", "", ""
	e.SubjectRefs = nil
	tx.state.Evidence[e.ID] = e
	for _, empty := range []bool{false, true} {
		d.StatusSummary = nil
		r.Warnings, r.UnsupportedFields, r.InvalidStatements, r.MappingFailures = nil, nil, nil, nil
		if empty {
			d.StatusSummary = map[string]int{}
			r.Warnings, r.UnsupportedFields = []string{}, []string{}
			r.InvalidStatements, r.MappingFailures = []domain.VEXImportIssue{}, []domain.VEXImportIssue{}
		}
		tx.state.VEXDocuments[d.ID], tx.state.VEXImportReports[r.ID] = d, r
		point, err := reader.GetVEXImportReportPoint(t.Context(), "tenant", "vex")
		if err != nil || point.Document.ProductID != "tenant-product" || point.Document.Document.ReleaseID != "" || (point.Document.Document.StatusSummary != nil) != empty || (point.Report.Warnings != nil) != empty || (point.Report.UnsupportedFields != nil) != empty || (point.Report.InvalidStatements != nil) != empty || (point.Report.MappingFailures != nil) != empty {
			t.Fatal("release-less point lost product authority or collection shape", point, err)
		}
		if value, err := query.GetVEXImportReport(t.Context(), actor, "vex"); err != nil || value.ID != r.ID {
			t.Fatal("product-granted reader lost release-less report", value, err)
		}
		denied := actor
		denied.ResourceGrants = []domain.ResourceGrant{{ResourceType: "release", ResourceID: "tenant-release", Scopes: []string{ScopeEvidenceRead}}}
		if _, err := query.GetVEXDocument(t.Context(), denied, "vex"); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("unrelated release grant authorized release-less product data", err)
		}
	}
}

func TestMemoryVEXPointsRejectMissingInputsCancellationAndClosedTransactions(t *testing.T) {
	tx, reader, _, _ := memoryVEXPointFixture(t)
	for _, point := range []struct {
		zero any
		read func(context.Context, string, string) (any, error)
	}{
		{evidencequery.VEXDocumentPoint{}, func(ctx context.Context, tenant, id string) (any, error) {
			return reader.GetVEXDocumentPoint(ctx, tenant, id)
		}},
		{evidencequery.VEXImportReportPoint{}, func(ctx context.Context, tenant, id string) (any, error) {
			return reader.GetVEXImportReportPoint(ctx, tenant, id)
		}},
	} {
		for _, input := range [][2]string{{"foreign", "vex"}, {"tenant", "missing"}, {"tenant", " \t "}, {"tenant", "report"}} {
			if value, err := point.read(t.Context(), input[0], input[1]); !errors.Is(err, evidencequery.ErrNotFound) || !reflect.DeepEqual(value, point.zero) {
				t.Fatal("foreign, missing or report-ID input exposed a VEX point", value, err)
			}
		}
		if value, err := point.read(nil, "tenant", "vex"); !errors.Is(err, evidencequery.ErrValidation) || !reflect.DeepEqual(value, point.zero) {
			t.Fatal("nil context exposed VEX metadata", value, err)
		}
		if value, err := point.read(t.Context(), "", "vex"); !errors.Is(err, evidencequery.ErrValidation) || !reflect.DeepEqual(value, point.zero) {
			t.Fatal("missing tenant exposed VEX metadata", value, err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		during := &memoryBundleCancelAfterSelection{Context: ctx, cancel: cancel}
		value, err := point.read(during, "tenant", "vex")
		cancel()
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, point.zero) {
			t.Fatal("canceled read retained a partial VEX point", value, err)
		}
		if _, err := point.read(t.Context(), "tenant", "vex"); err != nil {
			t.Fatal("cancellation retained the VEX reader lock", err)
		}
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if value, err := reader.GetVEXImportReportPoint(t.Context(), "tenant", "vex"); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, evidencequery.VEXImportReportPoint{}) {
		t.Fatal("closed repository exposed a VEX report", value, err)
	}
}
