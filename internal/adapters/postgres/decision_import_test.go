package postgres

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func importDecisionFixture(t *testing.T) (*Store, domain.VulnerabilityDecision) {
	t.Helper()
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 2, 12, 0, 0, 123456000, time.UTC)
	if err := store.ApplyCriticalMutation(ctx, app.CriticalMutation{Tenants: []domain.Tenant{{ID: "tenant", Name: "Tenant", CreatedAt: now}, {ID: "other", Name: "Other", CreatedAt: now}}}); err != nil {
		t.Fatal(err)
	}
	d := domain.VulnerabilityDecision{ID: "decision", TenantID: "tenant", FindingID: "finding", ScanID: "scan", ReleaseID: "release", Vulnerability: "CVE-TEST", Component: "component", SBOMID: "sbom", SBOMComponentPURL: "pkg:generic/api@1", SBOMComponentName: "API", Status: "affected", Justification: "Review", ImpactStatement: "Impact", ActionStatement: "Investigate", CustomerVisible: true, InternalNotes: "private marker", Source: "manual", EvidenceID: "evidence", EvidenceIDs: []string{"evidence"}, SupportingRefs: []domain.SubjectRef{{Type: "approval", ID: "approval"}}, VEXDocumentID: "vex", Supersedes: "legacy-root", ApprovedBy: "reviewer", ReviewedAt: &now, ReviewDueAt: &now, SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: now}
	if err := store.ApplyReleaseLedgerMutation(ctx, app.ReleaseLedgerMutation{VulnerabilityDecisions: []domain.VulnerabilityDecision{d}}); err != nil {
		t.Fatal(err)
	}
	return store, d
}

func rawImportedDecision(t *testing.T, store *Store) string {
	t.Helper()
	var row string
	if err := store.pool.QueryRow(t.Context(), `SELECT to_jsonb(d)::text FROM vulnerability_decisions d WHERE id='decision'`).Scan(&row); err != nil {
		t.Fatal(err)
	}
	return row
}

func TestPostgresDecisionImportRejectsEveryHistoricalContentChange(t *testing.T) {
	store, original := importDecisionFixture(t)
	before := rawImportedDecision(t, store)
	for _, test := range []struct {
		name   string
		change func(*domain.VulnerabilityDecision)
	}{
		{"tenant", func(d *domain.VulnerabilityDecision) { d.TenantID = "other" }},
		{"finding", func(d *domain.VulnerabilityDecision) { d.FindingID = "other-finding" }},
		{"scan", func(d *domain.VulnerabilityDecision) { d.ScanID = "other-scan" }},
		{"release", func(d *domain.VulnerabilityDecision) { d.ReleaseID = "other-release" }},
		{"vulnerability", func(d *domain.VulnerabilityDecision) { d.Vulnerability = "CVE-OTHER" }},
		{"component", func(d *domain.VulnerabilityDecision) { d.Component = "other-component" }},
		{"sbom", func(d *domain.VulnerabilityDecision) { d.SBOMID = "other-sbom" }},
		{"purl", func(d *domain.VulnerabilityDecision) { d.SBOMComponentPURL = "pkg:generic/other@1" }},
		{"component name", func(d *domain.VulnerabilityDecision) { d.SBOMComponentName = "Other" }},
		{"status", func(d *domain.VulnerabilityDecision) { d.Status = "fixed" }},
		{"justification", func(d *domain.VulnerabilityDecision) { d.Justification = "Different review" }},
		{"impact", func(d *domain.VulnerabilityDecision) { d.ImpactStatement = "Different impact" }},
		{"action", func(d *domain.VulnerabilityDecision) { d.ActionStatement = "Different action" }},
		{"visibility", func(d *domain.VulnerabilityDecision) { d.CustomerVisible = false }},
		{"notes", func(d *domain.VulnerabilityDecision) { d.InternalNotes = "different private notes" }},
		{"source", func(d *domain.VulnerabilityDecision) { d.Source = "vex" }},
		{"evidence", func(d *domain.VulnerabilityDecision) { d.EvidenceID = "other-evidence" }},
		{"evidence IDs", func(d *domain.VulnerabilityDecision) { d.EvidenceIDs = []string{"other-evidence"} }},
		{"support", func(d *domain.VulnerabilityDecision) {
			d.SupportingRefs = []domain.SubjectRef{{Type: "approval", ID: "other-approval"}}
		}},
		{"vex", func(d *domain.VulnerabilityDecision) { d.VEXDocumentID = "other-vex" }},
		{"supersedes", func(d *domain.VulnerabilityDecision) { d.Supersedes = "other-root" }},
		{"approver", func(d *domain.VulnerabilityDecision) { d.ApprovedBy = "other-reviewer" }},
		{"review time", func(d *domain.VulnerabilityDecision) { changed := d.ReviewedAt.Add(time.Hour); d.ReviewedAt = &changed }},
		{"due time", func(d *domain.VulnerabilityDecision) {
			changed := d.ReviewDueAt.Add(time.Hour)
			d.ReviewDueAt = &changed
		}},
		{"schema", func(d *domain.VulnerabilityDecision) { d.SchemaVersion = "other.v1" }},
		{"creation time", func(d *domain.VulnerabilityDecision) { d.CreatedAt = d.CreatedAt.Add(time.Hour) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := original
			test.change(&d)
			err := store.ApplyReleaseLedgerMutation(t.Context(), app.ReleaseLedgerMutation{VulnerabilityDecisions: []domain.VulnerabilityDecision{d}})
			rejected := errors.Is(err, app.ErrConflict) || test.name == "tenant" && errors.Is(err, app.ErrNotFound)
			if !rejected {
				t.Fatal("historical content mismatch was not rejected", err)
			}
			if rawImportedDecision(t, store) != before {
				t.Fatal("rejected import changed historical content")
			}
		})
	}
}

func TestPostgresDecisionImportReplayCannotReactivateHistory(t *testing.T) {
	store, root := importDecisionFixture(t)
	ctx := t.Context()
	before := rawImportedDecision(t, store)
	prior := root
	prior.SupersededBy = "successor"
	next := root
	next.ID, next.Supersedes, next.Status = "successor", root.ID, "fixed"
	next.CreatedAt = root.CreatedAt.Add(time.Hour)
	batch := app.ReleaseLedgerMutation{VulnerabilityDecisions: []domain.VulnerabilityDecision{prior, next}}
	for _, replay := range []app.ReleaseLedgerMutation{batch, batch, {VulnerabilityDecisions: []domain.VulnerabilityDecision{root}}} {
		if err := store.ApplyReleaseLedgerMutation(ctx, replay); err != nil {
			t.Fatal("safe import replay failed", err)
		}
		if rawImportedDecision(t, store) != before {
			t.Fatal("import replay rewrote historical content")
		}
	}
	state, exists, err := store.LoadState(ctx)
	if err != nil || !exists || state.Decisions[root.ID].SupersededBy != next.ID {
		t.Fatal("relational state did not project the appended successor", exists, err)
	}
	if err := store.SaveRelationalState(ctx, state); err != nil {
		t.Fatal("replaying projected relational state failed", err)
	}
	if rawImportedDecision(t, store) != before {
		t.Fatal("projected state replay rewrote original stored supersession fields")
	}
	var links, heads int
	var recordedAt time.Time
	if err := store.pool.QueryRow(ctx, `SELECT count(*),min(created_at) FROM vulnerability_decision_supersessions`).Scan(&links, &recordedAt); err != nil || links != 1 || !recordedAt.Equal(next.CreatedAt) {
		t.Fatal("replay duplicated the link or used the predecessor timestamp", links, recordedAt, err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM vulnerability_decision_projection WHERE superseded_by IS NULL`).Scan(&heads); err != nil || heads != 1 {
		t.Fatal("replay reactivated the predecessor", heads, err)
	}
}

func TestPostgresDecisionImportRollsBackFailedSuccessors(t *testing.T) {
	store, root := importDecisionFixture(t)
	before := rawImportedDecision(t, store)
	for _, test := range []struct {
		name   string
		change func(*app.ReleaseLedgerMutation)
	}{
		{"missing successor", func(m *app.ReleaseLedgerMutation) { m.VulnerabilityDecisions = m.VulnerabilityDecisions[:1] }},
		{"foreign successor", func(m *app.ReleaseLedgerMutation) { m.VulnerabilityDecisions[1].TenantID = "other" }},
		{"different finding", func(m *app.ReleaseLedgerMutation) { m.VulnerabilityDecisions[1].FindingID = "other-finding" }},
		{"successor insert failure", func(m *app.ReleaseLedgerMutation) { m.VulnerabilityDecisions[1].Justification = "invalid\x00text" }},
		{"late outbox failure", func(m *app.ReleaseLedgerMutation) {
			m.OutboxJobs = []app.OutboxJob{{ID: "job", TenantID: "tenant", Kind: "test", SubjectType: "vulnerability_decision", SubjectID: "pending", Payload: map[string]any{"invalid": math.NaN()}, CreatedAt: root.CreatedAt}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			prior, next := root, root
			prior.SupersededBy = "pending"
			next.ID, next.Supersedes, next.Status = "pending", root.ID, "fixed"
			next.CreatedAt = root.CreatedAt.Add(time.Hour)
			m := app.ReleaseLedgerMutation{VulnerabilityDecisions: []domain.VulnerabilityDecision{prior, next}}
			test.change(&m)
			if err := store.ApplyReleaseLedgerMutation(t.Context(), m); err == nil {
				t.Fatal("invalid or interrupted successor committed")
			}
			if rawImportedDecision(t, store) != before {
				t.Fatal("failed successor changed historical content")
			}
			var decisions, links, heads int
			var head string
			if err := store.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM vulnerability_decisions),(SELECT count(*) FROM vulnerability_decision_supersessions),(SELECT count(*) FROM vulnerability_decision_heads),(SELECT decision_id FROM vulnerability_decision_heads WHERE tenant_id='tenant' AND finding_id='finding')`).Scan(&decisions, &links, &heads, &head); err != nil || decisions != 1 || links != 0 || heads != 1 || head != root.ID {
				t.Fatal("failed successor leaked rows or changed the active head", decisions, links, heads, head, err)
			}
		})
	}
}

func TestPostgresDecisionImportNormalizesEmptyCollectionsAndPreservesFallbackClock(t *testing.T) {
	store, _ := importDecisionFixture(t)
	d := domain.VulnerabilityDecision{ID: "minimal", TenantID: "tenant", FindingID: "minimal-finding", ScanID: "scan", Vulnerability: "CVE-MINIMAL", Status: "affected", Justification: "Review", Source: "manual", SchemaVersion: domain.VulnerabilityDecisionVersion}
	if err := store.ApplyReleaseLedgerMutation(t.Context(), app.ReleaseLedgerMutation{VulnerabilityDecisions: []domain.VulnerabilityDecision{d}}); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := store.pool.QueryRow(t.Context(), `SELECT to_jsonb(d)::text FROM vulnerability_decisions d WHERE id='minimal'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	d.EvidenceIDs, d.SupportingRefs = []string{}, []domain.SubjectRef{}
	if err := store.ApplyReleaseLedgerMutation(t.Context(), app.ReleaseLedgerMutation{VulnerabilityDecisions: []domain.VulnerabilityDecision{d}}); err != nil {
		t.Fatal("empty arrays or unspecified creation time caused a false conflict", err)
	}
	var after string
	if err := store.pool.QueryRow(t.Context(), `SELECT to_jsonb(d)::text FROM vulnerability_decisions d WHERE id='minimal'`).Scan(&after); err != nil || after != before {
		t.Fatal("replay replaced the stored fallback clock or nullable fields", err)
	}
	for _, test := range []struct {
		name   string
		change func(*domain.VulnerabilityDecision)
	}{
		{"notes", func(d *domain.VulnerabilityDecision) { d.InternalNotes = "new private notes" }},
		{"approver", func(d *domain.VulnerabilityDecision) { d.ApprovedBy = "reviewer" }},
		{"review date", func(d *domain.VulnerabilityDecision) {
			now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
			d.ReviewedAt = &now
		}},
		{"review due date", func(d *domain.VulnerabilityDecision) {
			now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
			d.ReviewDueAt = &now
		}},
		{"sbom", func(d *domain.VulnerabilityDecision) { d.SBOMID = "sbom" }},
		{"purl", func(d *domain.VulnerabilityDecision) { d.SBOMComponentPURL = "pkg:generic/api@1" }},
		{"name", func(d *domain.VulnerabilityDecision) { d.SBOMComponentName = "API" }},
		{"visibility", func(d *domain.VulnerabilityDecision) { d.CustomerVisible = true }},
		{"evidence IDs", func(d *domain.VulnerabilityDecision) { d.EvidenceIDs = []string{"evidence"} }},
		{"supporting references", func(d *domain.VulnerabilityDecision) {
			d.SupportingRefs = []domain.SubjectRef{{Type: "approval", ID: "approval"}}
		}},
	} {
		t.Run("cannot enrich historical "+test.name, func(t *testing.T) {
			changed := d
			test.change(&changed)
			if err := store.ApplyReleaseLedgerMutation(t.Context(), app.ReleaseLedgerMutation{VulnerabilityDecisions: []domain.VulnerabilityDecision{changed}}); !errors.Is(err, app.ErrConflict) {
				t.Fatal("import enriched an existing historical row", err)
			}
			if err := store.pool.QueryRow(t.Context(), `SELECT to_jsonb(d)::text FROM vulnerability_decisions d WHERE id='minimal'`).Scan(&after); err != nil || after != before {
				t.Fatal("rejected enrichment changed content", err)
			}
		})
	}
}

func TestPostgresDecisionImportRetainsInitialLegacySuccessorFields(t *testing.T) {
	store, root := importDecisionFixture(t)
	root.ID, root.FindingID, root.Supersedes, root.SupersededBy = "legacy-import-root", "legacy-finding", "", "legacy-import-next"
	next := root
	next.ID, next.Supersedes, next.SupersededBy = root.SupersededBy, root.ID, ""
	batch := app.ReleaseLedgerMutation{VulnerabilityDecisions: []domain.VulnerabilityDecision{next, root}}
	if err := store.ApplyReleaseLedgerMutation(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	var before, after, successor string
	var links int
	if err := store.pool.QueryRow(t.Context(), `SELECT to_jsonb(d)::text,superseded_by FROM vulnerability_decisions d WHERE id='legacy-import-root'`).Scan(&before, &successor); err != nil || successor != next.ID {
		t.Fatal("initial legacy row did not retain its stored successor field", successor, err)
	}
	if err := store.ApplyReleaseLedgerMutation(t.Context(), batch); err != nil {
		t.Fatal("legacy history replay failed", err)
	}
	if err := store.pool.QueryRow(t.Context(), `SELECT to_jsonb(d)::text FROM vulnerability_decisions d WHERE id='legacy-import-root'`).Scan(&after); err != nil || before != after {
		t.Fatal("legacy history was rewritten", err)
	}
	if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM vulnerability_decision_supersessions`).Scan(&links); err != nil || links != 0 {
		t.Fatal("legacy import fabricated new relationship history", links, err)
	}
}
