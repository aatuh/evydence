package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresVEXPointsCheckCurrentParentsAndReportLinkage(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"ten_vex_point", "ten_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id, name, created_at) VALUES ($1, $1, $2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, parent := range []struct{ suffix, tenant string }{{"a", "ten_vex_point"}, {"b", "ten_vex_point"}, {"other", "ten_other"}} {
		digestChar := "a"
		switch parent.suffix {
		case "b":
			digestChar = "b"
		case "other":
			digestChar = "c"
		}
		hash := "sha256:" + strings.Repeat(digestChar, 64)
		if _, err := store.pool.Exec(ctx, `INSERT INTO products (id, tenant_id, name, slug, created_at) VALUES ($1, $2, $1, $1, $3)`, "prod_"+parent.suffix, parent.tenant, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO releases (id, tenant_id, product_id, version, state, created_at) VALUES ($1, $2, $3, '1.0.0', 'draft', $4)`, "rel_"+parent.suffix, parent.tenant, "prod_"+parent.suffix, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at) VALUES ($1, $2, 'Artifact', 'application/octet-stream', 1, $3, $4)`, "art_"+parent.suffix, parent.tenant, hash, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, subject_refs, trust_level, verification_status, created_at) VALUES ($1, $2, $3, $4, 'vex', 'VEX', 'test', $5, 1, 'evidence-item.v1.0.0', $6, $6, 'canonical-json.v1', jsonb_build_array(jsonb_build_object('type', 'artifact', 'id', $7::text)), 'L2', 'pending', $5)`, "ev_"+parent.suffix, parent.tenant, "prod_"+parent.suffix, "rel_"+parent.suffix, now, hash, "art_"+parent.suffix); err != nil {
			t.Fatal(err)
		}
	}
	for _, record := range []struct{ id, tenant, evidence, release, artifact string }{
		{"vex_good", "ten_vex_point", "ev_a", "rel_a", "art_a"},
		{"vex_no_report", "ten_vex_point", "ev_b", "rel_b", "art_b"},
		{"vex_wrong_release", "ten_vex_point", "ev_b", "rel_a", "art_b"},
		{"vex_wrong_artifact", "ten_vex_point", "ev_a", "rel_a", "art_b"},
		{"vex_foreign_source", "ten_vex_point", "ev_other", "rel_a", "art_a"},
		{"vex_other", "ten_other", "ev_other", "rel_other", "art_other"},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO vex_documents (id, tenant_id, evidence_id, release_id, artifact_id, format, author, version, statement_count, status_summary, schema_version, created_at) VALUES ($1, $2, $3, $4, $5, 'openvex', 'author', '1', 1, '{"not_affected":1}'::jsonb, 'vex-document.v1', $6)`, record.id, record.tenant, record.evidence, record.release, record.artifact, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO vex_import_reports (id, tenant_id, vex_document_id, evidence_id, release_id, artifact_id, parser_version, status, statement_count, decisions_created, decisions_superseded, unsupported_fields, warnings, invalid_statements, mapping_failures, schema_version, created_at, updated_at) VALUES ('report_good', 'ten_vex_point', 'vex_good', 'ev_a', 'rel_a', 'art_a', 'openvex.v1', 'parsed', 1, 1, 0, ARRAY['extra']::text[], '["safe warning"]'::jsonb, '[]'::jsonb, '[{"statement_index":1,"code":"unmatched","detail":"No match."}]'::jsonb, 'vex-import-report.v1', $1, $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO vex_import_reports (id, tenant_id, vex_document_id, evidence_id, release_id, artifact_id, parser_version, status, schema_version, created_at, updated_at) VALUES ('report_foreign', 'ten_other', 'vex_good', 'ev_other', 'rel_other', 'art_other', 'openvex.v1', 'accepted', 'vex-import-report.v1', $1, $1)`, now); err != nil {
		t.Fatal(err)
	}
	service, err := evidencequery.NewVEXPoints(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_vex_point", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_a", Scopes: []string{"evidence:read"}}}}
	got, err := service.GetVEXDocument(ctx, actor, "vex_good")
	if err != nil || got.ID != "vex_good" || got.StatusSummary["not_affected"] != 1 {
		t.Fatalf("document=%#v error=%v", got, err)
	}
	report, err := service.GetVEXImportReport(ctx, actor, "vex_good")
	if err != nil || report.ID != "report_good" || report.Status != "parsed" || len(report.MappingFailures) != 1 || report.MappingFailures[0].Code != "unmatched" || len(report.Warnings) != 1 || len(report.UnsupportedFields) != 1 {
		t.Fatalf("report=%#v error=%v", report, err)
	}
	job := ClaimedJob{TenantID: "ten_vex_point", Kind: "parse_vex", SubjectType: "vex_document", SubjectID: "vex_good", Payload: map[string]any{"import_report_id": "report_good", "actor_type": "api_key", "actor_id": "key_a", "payload_hash": "sha256:" + strings.Repeat("a", 64)}}
	state, ok, err := store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.VEXDocuments) != 1 || state.VEXDocuments[job.SubjectID].EvidenceID != "ev_a" || len(state.VEXImportReports) != 1 || state.VEXImportReports["report_good"].Status != "parsed" || state.Evidence["ev_a"].TenantID != job.TenantID {
		t.Fatalf("focused VEX state document=%#v report=%#v evidence=%#v ok=%v error=%v", state.VEXDocuments, state.VEXImportReports, state.Evidence, ok, err)
	}
	job.TenantID = "ten_other"
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.VEXDocuments) != 0 || len(state.VEXImportReports) != 0 {
		t.Fatalf("foreign VEX state document=%#v report=%#v ok=%v error=%v", state.VEXDocuments, state.VEXImportReports, ok, err)
	}
	for _, record := range []struct{ suffix, release, product, finding string }{{"a", "rel_a", "prod_a", "finding_a"}, {"b", "rel_b", "prod_b", "finding_b"}} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO evidence_items (id, tenant_id, product_id, release_id, type, title, source_system, observed_at, evidence_version, schema_version, payload_hash, canonical_hash, canonicalization, trust_level, verification_status, created_at) VALUES ($1, 'ten_vex_point', $2, $3, 'vulnerability_scan', 'Scan', 'test', $4, 1, 'evidence-item.v1.0.0', $5, $5, 'canonical-json.v1', 'L2', 'pending', $4)`, "ev_scan_"+record.suffix, record.product, record.release, now, "sha256:"+strings.Repeat("d", 64)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO vulnerability_scans (id, tenant_id, evidence_id, release_id, scanner, target_ref, summary, findings, created_at) VALUES ($1, 'ten_vex_point', $2, $3, 'scanner', 'target', '{}'::jsonb, jsonb_build_array(jsonb_build_object('id', $4::text, 'vulnerability', 'CVE-1', 'component', 'pkg:oci/api')), $5)`, "scan_"+record.suffix, "ev_scan_"+record.suffix, record.release, record.finding, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO vulnerability_decisions (id, tenant_id, finding_id, scan_id, release_id, vulnerability, status, justification, source, schema_version, created_at) VALUES ($1, 'ten_vex_point', $2, $3, $4, 'CVE-1', 'affected', 'test', 'manual', 'v1', $5)`, "decision_"+record.suffix, record.finding, "scan_"+record.suffix, record.release, now); err != nil {
			t.Fatal(err)
		}
	}
	auditState := app.PersistedState{Chain: map[string][]domain.AuditChainEntry{}}
	accepted, err := app.AppendPersistedChainEntry(&auditState, now, "ten_vex_point", "vex.accepted", "vex_document", "vex_good", "api_key", "key_a", "sha256:"+strings.Repeat("a", 64), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, app.ReleaseLedgerMutation{AuditChainEntries: []domain.AuditChainEntry{accepted}}); err != nil {
		t.Fatal(err)
	}
	job.TenantID = "ten_vex_point"
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.Scans) != 1 || state.Scans["scan_a"].ID != "scan_a" || len(state.Decisions) != 1 || state.Decisions["decision_a"].ID != "decision_a" || len(state.Chain[job.TenantID]) != 1 || state.Chain[job.TenantID][0].ID != accepted.ID {
		t.Fatalf("release-scoped VEX dependencies scans=%#v decisions=%#v chain=%#v ok=%v error=%v", state.Scans, state.Decisions, state.Chain, ok, err)
	}
	var last domain.AuditChainEntry
	for index := range 3 {
		last, err = app.AppendPersistedChainEntry(&auditState, now.Add(time.Duration(index+1)*time.Second), job.TenantID, "unrelated.event", "release", "rel_b", "api_key", "key_a", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.ApplyReleaseLedgerMutation(ctx, app.ReleaseLedgerMutation{AuditChainEntries: []domain.AuditChainEntry{last}}); err != nil {
			t.Fatal(err)
		}
	}
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.Chain[job.TenantID]) != 2 || state.Chain[job.TenantID][0].ID != accepted.ID || state.Chain[job.TenantID][1].ID != last.ID {
		t.Fatalf("VEX job loaded more than accepted entry and tip: chain=%#v ok=%v error=%v", state.Chain, ok, err)
	}
	proposed, err := app.AppendPersistedChainEntry(&state, now.Add(4*time.Second), job.TenantID, "unrelated.event", "release", "rel_a", "api_key", "key_a", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, app.ReleaseLedgerMutation{AuditChainEntries: []domain.AuditChainEntry{proposed}}); err != nil {
		t.Fatalf("rebase sparse VEX audit append: %v", err)
	}
	state, ok, err = store.LoadWorkerJobState(ctx, job)
	if err != nil || !ok || len(state.Chain[job.TenantID]) != 2 || state.Chain[job.TenantID][1].ID != proposed.ID || state.Chain[job.TenantID][1].Sequence != 5 {
		t.Fatalf("rebased sparse VEX append chain=%#v ok=%v error=%v", state.Chain, ok, err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_b"
	if _, err := service.GetVEXDocument(ctx, actor, "vex_good"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong document grant error=%v", err)
	}
	if _, err := service.GetVEXImportReport(ctx, actor, "vex_good"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("wrong report grant error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "rel_a", Scopes: []string{"evidence:read"}}
	if _, err := service.GetVEXImportReport(ctx, actor, "vex_good"); err != nil {
		t.Fatalf("release grant error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: "ten_vex_point", Scopes: []string{"evidence:read"}}
	if _, err := service.GetVEXImportReport(ctx, actor, "vex_no_report"); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("missing report error=%v", err)
	}
	for _, id := range []string{"vex_wrong_release", "vex_wrong_artifact", "vex_foreign_source", "vex_other", "vex_missing"} {
		if _, err := service.GetVEXDocument(ctx, actor, id); !errors.Is(err, evidencequery.ErrNotFound) {
			t.Fatalf("unsafe document %s error=%v", id, err)
		}
	}
	if _, err := store.pool.Exec(ctx, `UPDATE vex_import_reports SET evidence_id='ev_b' WHERE id='report_good'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetVEXImportReport(ctx, actor, "vex_good"); !errors.Is(err, evidencequery.ErrConflict) {
		t.Fatalf("unlinked report error=%v", err)
	}
	if _, _, err := store.LoadWorkerJobState(ctx, job); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("focused worker accepted unlinked report: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE vex_import_reports SET evidence_id='ev_a' WHERE id='report_good'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE vex_import_reports SET artifact_id='art_b' WHERE id='report_good'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetVEXImportReport(ctx, actor, "vex_good"); !errors.Is(err, evidencequery.ErrConflict) {
		t.Fatalf("unlinked report artifact error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE vex_import_reports SET artifact_id='art_a' WHERE id='report_good'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO vex_import_reports (id, tenant_id, vex_document_id, evidence_id, release_id, artifact_id, parser_version, status, schema_version, created_at, updated_at) VALUES ('report_duplicate', 'ten_vex_point', 'vex_good', 'ev_a', 'rel_a', 'art_a', 'openvex.v1', 'accepted', 'vex-import-report.v1', $1, $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetVEXImportReport(ctx, actor, "vex_good"); !errors.Is(err, evidencequery.ErrConflict) {
		t.Fatalf("ambiguous reports error=%v", err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, product_id, name, created_at) VALUES ('proj_b', 'ten_vex_point', 'prod_b', 'Project B', $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET project_id='proj_b' WHERE id='ev_a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetVEXDocument(ctx, actor, "vex_good"); !errors.Is(err, evidencequery.ErrNotFound) {
		t.Fatalf("cross-product source project error=%v", err)
	}
}
