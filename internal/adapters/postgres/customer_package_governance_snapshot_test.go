package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var customerGovernanceNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func mutateCustomerGovernanceFixture(t *testing.T, s *Store, sql, restore string) {
	t.Helper()
	if _, err := s.pool.Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if _, err := s.pool.Exec(ctx, restore); err != nil {
			t.Error("restore governance fixture", err)
		}
	})
}

func customerGovernanceProfile() packagedomain.RedactionProfile {
	return packagedomain.RedactionProfile{ID: "profile", TenantID: "tenant", AllowedTypes: []string{"vulnerability_decision"}}
}

func customerGovernanceFixture(t *testing.T) *Store {
	t.Helper()
	s := customerEvidenceFixture(t)
	for _, sql := range []string{
		`UPDATE vulnerability_scans SET findings='[{"id":"finding_selected","vulnerability":"CVE-1","component":"component","private":"private-finding-marker"}]' WHERE id='vulnerability_scan_selected'`,
		`INSERT INTO control_frameworks(id,tenant_id,name,slug,version,status,schema_version,created_at) VALUES('framework','tenant','Public','public','1','active','framework.v1','2026-10-01T00:00:00Z'),('foreign_framework','foreign_tenant','Foreign','foreign','1','active','framework.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO security_controls(id,tenant_id,framework_id,code,title,objective,evidence_requirements,applicability,limitations,schema_version,created_at) VALUES('control','tenant','framework','C','Public','private-objective-marker','[]','[]','[]','control.v1','2026-10-01T00:00:00Z'),('foreign_control','foreign_tenant','foreign_framework','F','Foreign','private-objective-marker','[]','[]','[]','control.v1','2026-10-01T00:00:00Z'),('broken_control','tenant','foreign_framework','B','Broken','private-objective-marker','[]','[]','[]','control.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO approval_records(id,tenant_id,subject_type,subject_id,decision,reason,approver_id,evidence_id,schema_version,created_at) VALUES
		 ('approval_release','tenant','release','release','approve','reviewed','private-approver-marker','ev_selected','approval.v1','2026-10-01T00:00:00Z'),
		 ('approval_product','tenant','product','product','approve','reviewed','private-approver-marker',NULL,'approval.v1','2026-10-01T00:00:00Z'),
		 ('approval_sibling','tenant','release','sibling_release','approve','private-sibling-marker','private-approver-marker',NULL,'approval.v1','2026-10-01T00:00:00Z'),
		 ('approval_foreign','foreign_tenant','release','release','approve','private-foreign-marker','private-approver-marker',NULL,'approval.v1','2026-10-01T00:00:00Z'),
		 ('approval_bad_evidence','tenant','release','release','approve','private-bad-reference-marker','private-approver-marker','ev_sibling','approval.v1','2026-10-01T00:00:00Z'),
		 ('approval_other_kind','tenant','waiver','waiver_release','approve','private-other-kind-marker','private-approver-marker',NULL,'approval.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO exceptions(id,tenant_id,release_id,finding_id,control_id,reason,owner,expires_at,approved,approved_by,approved_at,created_at) VALUES
		 ('exception_release','tenant','release','finding_selected','control','reviewed','security','2026-10-05T00:00:00Z',true,'private-approver-marker','2026-10-02T00:00:00Z','2026-10-01T00:00:00Z'),
		 ('exception_expired','tenant','release',NULL,NULL,'private-expired-marker','security','2026-10-04T12:00:00Z',true,NULL,NULL,'2026-10-01T00:00:00Z'),
		 ('exception_pending','tenant','release',NULL,NULL,'private-pending-marker','security','2026-10-05T00:00:00Z',false,NULL,NULL,'2026-10-01T00:00:00Z'),
		 ('exception_sibling','tenant','sibling_release',NULL,NULL,'private-sibling-marker','security','2026-10-05T00:00:00Z',true,NULL,NULL,'2026-10-01T00:00:00Z'),
		 ('exception_foreign','foreign_tenant','release',NULL,NULL,'private-foreign-marker','security','2026-10-05T00:00:00Z',true,NULL,NULL,'2026-10-01T00:00:00Z'),
		 ('exception_bad_control','tenant','release',NULL,'broken_control','private-bad-control-marker','security','2026-10-05T00:00:00Z',true,NULL,NULL,'2026-10-01T00:00:00Z'),
		 ('exception_bad_finding','tenant','release','missing',NULL,'private-bad-finding-marker','security','2026-10-05T00:00:00Z',true,NULL,NULL,'2026-10-01T00:00:00Z')`,
		`INSERT INTO waivers(id,tenant_id,scope_type,scope_id,control_id,owner,risk,reason,expires_at,approved,approved_by,approved_at,schema_version,created_at) VALUES
		 ('waiver_release','tenant','release','release','control','security','accepted','reviewed','2026-10-05T00:00:00Z',true,'private-approver-marker','2026-10-02T00:00:00Z','waiver.v1','2026-10-01T00:00:00Z'),
		 ('waiver_product','tenant','product','product',NULL,'security','accepted','reviewed','2026-10-05T00:00:00Z',true,'private-approver-marker',NULL,'waiver.v1','2026-10-01T00:00:00Z'),
		 ('waiver_expired','tenant','release','release',NULL,'security','accepted','private-expired-marker','2026-10-04T12:00:00Z',true,NULL,NULL,'waiver.v1','2026-10-01T00:00:00Z'),
		 ('waiver_pending','tenant','release','release',NULL,'security','accepted','private-pending-marker','2026-10-05T00:00:00Z',false,NULL,NULL,'waiver.v1','2026-10-01T00:00:00Z'),
		 ('waiver_sibling','tenant','product','sibling',NULL,'security','accepted','private-sibling-marker','2026-10-05T00:00:00Z',true,NULL,NULL,'waiver.v1','2026-10-01T00:00:00Z'),
		 ('waiver_bad_control','tenant','release','release','foreign_control','security','accepted','private-bad-control-marker','2026-10-05T00:00:00Z',true,NULL,NULL,'waiver.v1','2026-10-01T00:00:00Z'),
		 ('waiver_other_kind','tenant','control','control',NULL,'security','accepted','private-other-kind-marker','2026-10-05T00:00:00Z',true,NULL,NULL,'waiver.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO questionnaire_answer_library(id,tenant_id,question_id,product_id,release_id,answer,evidence_ids,limitations,schema_version,created_at) VALUES
		 ('answer_release','tenant','Q','product','release','reviewed',ARRAY['ev_selected'],ARRAY['human review required'],'answer.v1','2026-10-01T00:00:00Z'),
		 ('answer_product','tenant','Q','product',NULL,'reviewed','{}','{}','answer.v1','2026-10-01T00:00:00Z'),
		 ('answer_global','tenant','Q',NULL,NULL,'reviewed','{}','{}','answer.v1','2026-10-01T00:00:00Z'),
		 ('answer_sibling','tenant','Q','sibling',NULL,'private-sibling-marker','{}','{}','answer.v1','2026-10-01T00:00:00Z'),
		 ('answer_bad_reference','tenant','Q',NULL,NULL,'private-bad-reference-marker',ARRAY['ev_sibling'],'{}','answer.v1','2026-10-01T00:00:00Z'),
		 ('answer_foreign','foreign_tenant','Q','product','release','private-foreign-marker','{}','{}','answer.v1','2026-10-01T00:00:00Z'),
		 ('answer_bad_release','tenant','Q','product','sibling_release','private-bad-release-marker','{}','{}','answer.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,release_id,vulnerability,component,status,justification,impact_statement,action_statement,source,evidence_id,evidence_ids,vex_document_id,sbom_id,sbom_component_purl,sbom_component_name,customer_visible,internal_notes,supporting_refs,reviewed_at,review_due_at,schema_version,created_at) VALUES
		 ('decision_selected','tenant','finding_selected','vulnerability_scan_selected','release','CVE-1','component','fixed','reviewed','impact','upgrade','manual','ev_selected',ARRAY['ev_selected'],'vex_selected','sbom_selected','purl','component',true,'private-notes-marker','[{"type":"approval","id":"approval_release","digest":"sha256:approval","private":"private-extension-marker"}]','2026-10-02T00:00:00Z','2026-10-06T00:00:00Z','decision.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,source,customer_visible,internal_notes,schema_version,created_at) VALUES
		 ('decision_hidden','tenant','hidden','vulnerability_scan_selected','release','CVE-HIDDEN','fixed','private-hidden-marker','manual',false,'private-notes-marker','decision.v1','2026-10-01T00:00:00Z'),
		 ('decision_bad_scan','tenant','bad_scan','vulnerability_scan_sibling','release','CVE-BAD','fixed','private-bad-scan-marker','manual',true,'private-notes-marker','decision.v1','2026-10-01T00:00:00Z')`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestCustomerPackageGovernanceSnapshotScopesAndRedactsMetadata(t *testing.T) {
	s := customerGovernanceFixture(t)
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	v, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []struct {
		rows []map[string]any
		ids  string
	}{{v.Decisions, "decision_selected"}, {v.Approvals, "approval_product,approval_release"}, {v.Exceptions, "exception_release"}, {v.Waivers, "waiver_product,waiver_release"}, {v.AnswerLibrary, "answer_global,answer_product,answer_release"}} {
		var ids []string
		for _, row := range part.rows {
			ids = append(ids, row["id"].(string))
		}
		if strings.Join(ids, ",") != part.ids {
			t.Fatalf("scope ids=%v want=%s", ids, part.ids)
		}
	}
	if v.Decisions[0]["reviewed_at"] != "2026-10-02T00:00:00Z" || v.Exceptions[0]["approved_at"] != "2026-10-02T00:00:00Z" || v.Waivers[1]["approved_at"] != "2026-10-02T00:00:00Z" || !reflect.DeepEqual(v.AnswerLibrary[2]["evidence_ids"], []string{"ev_selected"}) || !reflect.DeepEqual(v.AnswerLibrary[2]["limitations"], []string{"human review required"}) {
		t.Fatal("public metadata shape/time changed", v)
	}
	if refs := v.Decisions[0]["supporting_refs"].([]map[string]any); !reflect.DeepEqual(refs, []map[string]any{{"type": "approval", "id": "approval_release", "digest": "sha256:approval"}}) {
		t.Fatal("supporting reference projection changed", refs)
	}
	if ids := v.AnswerLibrary[0]["evidence_ids"].([]string); ids != nil {
		t.Fatal("empty public list must preserve legacy nil shape", ids)
	}
	body, err := json.Marshal(v)
	if err != nil || strings.Contains(string(body), "private-") || tx.privateFound {
		t.Fatal("private fields crossed storage boundary", string(body), tx.privateFound, err)
	}
	profile := customerGovernanceProfile()
	profile.ExcludedFields = []string{"reviewed_at", "evidence_ids", "supporting_refs"}
	redacted, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", profile, customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range profile.ExcludedFields {
		if _, present := redacted.Decisions[0][key]; present {
			t.Fatal("profile decision exclusion ignored", key)
		}
	}
	product, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(product.Decisions) != 0 || len(product.Exceptions) != 0 || len(product.Approvals) != 1 || product.Approvals[0]["id"] != "approval_product" || len(product.Waivers) != 1 || product.Waivers[0]["id"] != "waiver_product" || len(product.AnswerLibrary) != 2 {
		t.Fatalf("product-only scope=%#v err=%v", product, err)
	}
	var effects int
	if err := tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM customer_security_packages)+(SELECT count(*) FROM audit_chain_entries)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM outbox_jobs)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatalf("readonly snapshot effects=%d err=%v", effects, err)
	}
}

func TestCustomerPackageGovernanceSnapshotRejectsBadRootsAndInputs(t *testing.T) {
	s := customerGovernanceFixture(t)
	tx := customerCatalogReadTx(t, s)
	for _, scope := range [][3]string{{"tenant", "foreign_product", ""}, {"tenant", "product", "sibling_release"}, {"foreign_tenant", "product", "release"}, {"tenant", "product", "bad_parent"}} {
		profile := customerGovernanceProfile()
		profile.TenantID = scope[0]
		v, err := readCustomerPackageGovernanceTx(t.Context(), tx, scope[0], scope[1], scope[2], profile, customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
		if !errors.Is(err, packageapp.ErrNotFound) || !reflect.DeepEqual(v, customerPackageGovernanceSnapshot{}) {
			t.Fatalf("foreign root value=%#v err=%v", v, err)
		}
	}
	for _, at := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("east", 3600))} {
		if _, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceProfile(), at, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, packageapp.ErrValidation) {
			t.Fatal("invalid generation time accepted", at, err)
		}
	}
	for _, id := range []string{" product", "\u2003product", strings.Repeat("é", 513), "product\x00", string([]byte{0xff})} {
		if _, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", id, "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, packageapp.ErrValidation) {
			t.Fatal("invalid raw coordinate accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readCustomerPackageGovernanceTx(ctx, tx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCustomerPackageGovernanceSnapshotRejectsMalformedPublicFieldsBeforeTransfer(t *testing.T) {
	s := customerGovernanceFixture(t)
	for _, tc := range []struct{ name, sql, restore string }{
		{"supporting object", `UPDATE vulnerability_decisions SET supporting_refs='{}' WHERE id='decision_selected'`, `UPDATE vulnerability_decisions SET supporting_refs='[]' WHERE id='decision_selected'`},
		{"nested private reference", `UPDATE vulnerability_decisions SET supporting_refs='[{"type":"approval","id":{"token":"private-nested-marker"}}]' WHERE id='decision_selected'`, `UPDATE vulnerability_decisions SET supporting_refs='[]' WHERE id='decision_selected'`},
		{"reference array limit", `UPDATE vulnerability_decisions SET supporting_refs=(SELECT jsonb_agg(jsonb_build_object('type','approval','id','approval_release')) FROM generate_series(1,4097)) WHERE id='decision_selected'`, `UPDATE vulnerability_decisions SET supporting_refs='[]' WHERE id='decision_selected'`},
		{"null citation", `UPDATE questionnaire_answer_library SET evidence_ids=ARRAY[NULL]::text[] WHERE id='answer_release'`, `UPDATE questionnaire_answer_library SET evidence_ids=ARRAY['ev_selected'] WHERE id='answer_release'`},
		{"multidimensional citation", `UPDATE questionnaire_answer_library SET evidence_ids=ARRAY[['ev_selected']] WHERE id='answer_release'`, `UPDATE questionnaire_answer_library SET evidence_ids=ARRAY['ev_selected'] WHERE id='answer_release'`},
		{"multidimensional limitation", `UPDATE questionnaire_answer_library SET limitations=ARRAY[['private-nested-marker']] WHERE id='answer_release'`, `UPDATE questionnaire_answer_library SET limitations='{}' WHERE id='answer_release'`},
		{"multidimensional decision citation", `UPDATE vulnerability_decisions SET evidence_ids=ARRAY[['ev_selected']] WHERE id='decision_selected'`, `UPDATE vulnerability_decisions SET evidence_ids=ARRAY['ev_selected'] WHERE id='decision_selected'`},
		{"limitation limit", `UPDATE questionnaire_answer_library SET limitations=array_fill('review'::text,ARRAY[4097]) WHERE id='answer_release'`, `UPDATE questionnaire_answer_library SET limitations='{}' WHERE id='answer_release'`},
		{"large answer", `UPDATE questionnaire_answer_library SET answer=repeat('x',8388609) WHERE id='answer_release'`, `UPDATE questionnaire_answer_library SET answer='reviewed' WHERE id='answer_release'`},
		{"infinite approval", `UPDATE exceptions SET approved_at='infinity' WHERE id='exception_release'`, `UPDATE exceptions SET approved_at='2026-10-02T00:00:00Z' WHERE id='exception_release'`},
		{"infinite expiry", `UPDATE waivers SET expires_at='infinity' WHERE id='waiver_release'`, `UPDATE waivers SET expires_at='2026-10-05T00:00:00Z' WHERE id='waiver_release'`},
		{"invalid public year", `UPDATE approval_records SET created_at='10000-01-01T00:00:00Z' WHERE id='approval_release'`, `UPDATE approval_records SET created_at='2026-10-01T00:00:00Z' WHERE id='approval_release'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.sql, tc.restore)
			tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
			budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, budget)
			if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, customerPackageGovernanceSnapshot{}) || budget.remainingBytes != packageapp.MaxCustomerPackageManifestBytes || tx.privateFound || tx.largest > 4096 {
				t.Fatalf("invalid metadata result=%#v remaining=%d transfer=%d private=%v err=%v", v, budget.remainingBytes, tx.largest, tx.privateFound, err)
			}
		})
	}
}

func TestCustomerPackageGovernanceSnapshotKeepsOneViewAndCumulativeBudget(t *testing.T) {
	s := customerGovernanceFixture(t)
	tx := customerCatalogReadTx(t, s)
	budget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readCustomerPackageCatalogTx(t.Context(), tx, "tenant", "product", "release", budget); err != nil {
		t.Fatal(err)
	}
	if _, err := readCustomerPackageEvidenceTx(t.Context(), tx, "tenant", "product", "release", budget); err != nil {
		t.Fatal(err)
	}
	before, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, budget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE approval_records SET reason='after' WHERE id='approval_release'; UPDATE questionnaire_answer_library SET answer='after' WHERE id='answer_release'; UPDATE exceptions SET approved=false WHERE id='exception_release'`); err != nil {
		t.Fatal(err)
	}
	stillBefore, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || !reflect.DeepEqual(before, stillBefore) {
		t.Fatalf("mixed snapshot=%#v err=%v", stillBefore, err)
	}
	newTx := customerCatalogReadTx(t, s)
	freshBudget := &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	after, err := readCustomerPackageGovernanceTx(t.Context(), newTx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, freshBudget)
	if err != nil || after.Approvals[1]["reason"] != "after" || after.AnswerLibrary[2]["answer"] != "after" || len(after.Exceptions) != 0 {
		t.Fatalf("fresh snapshot=%#v err=%v", after, err)
	}
	used := packageapp.MaxCustomerPackageManifestBytes - freshBudget.remainingBytes
	for _, remaining := range []int{1, used - 1} {
		budget := &customerSnapshotBudget{remainingBytes: remaining}
		v, err := readCustomerPackageGovernanceTx(t.Context(), newTx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, budget)
		if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, customerPackageGovernanceSnapshot{}) || budget.remainingBytes != remaining {
			t.Fatalf("partial/over-budget component=%#v remaining=%d err=%v", v, budget.remainingBytes, err)
		}
	}
	// Expiry is tied to generation time, not the clock at each SQL query.
	expired, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow.Add(48*time.Hour), &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(expired.Exceptions)+len(expired.Waivers) != 0 {
		t.Fatalf("fixed-time expiry=%#v err=%v", expired, err)
	}
}

func TestCustomerPackageGovernanceSnapshotBoundsRowsWithoutTruncating(t *testing.T) {
	s := customerGovernanceFixture(t)
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO approval_records(id,tenant_id,subject_type,subject_id,decision,reason,approver_id,schema_version,created_at)
	 SELECT 'overflow_'||n,'tenant','product','product','approve','reviewed','private-approver-marker','approval.v1','2026-10-01T00:00:00Z' FROM generate_series(1,4095)n`); err != nil {
		t.Fatal(err)
	}
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	v, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if !errors.Is(err, packageapp.ErrConflict) || !reflect.DeepEqual(v, customerPackageGovernanceSnapshot{}) || tx.largest > 4096 || tx.privateFound {
		t.Fatalf("row overflow result=%#v transfer=%d err=%v", v, tx.largest, err)
	}
	if _, err := s.pool.Exec(t.Context(), `DELETE FROM approval_records WHERE id='overflow_4095'`); err != nil {
		t.Fatal(err)
	}
	v, err = readCustomerPackageGovernanceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.Approvals) != packageapp.MaxSecurityReviewEvidenceIDs || len(v.Decisions) != 1 {
		t.Fatalf("exact row boundary rejected: approvals=%d decisions=%d err=%v", len(v.Approvals), len(v.Decisions), err)
	}
}

func TestCustomerPackageGovernanceSnapshotRetainsOwnedSupportingReferenceKinds(t *testing.T) {
	s := customerGovernanceFixture(t)
	for _, sql := range []string{
		`INSERT INTO release_bundles(id,tenant_id,release_id,state,manifest,manifest_hash,signature_refs) VALUES('bundle','tenant','release','draft','{}','sha256:fixture','[]')`,
		`INSERT INTO incidents(id,tenant_id,product_id,release_id,title,severity,status,opened_at,schema_version,created_at) VALUES('incident','tenant','product','release','private-title-marker','high','open','2026-10-01T00:00:00Z','incident.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO remediation_tasks(id,tenant_id,incident_id,title,owner,status,evidence_id,schema_version,created_at) VALUES('task','tenant','incident','private-title-marker','security','open','ev_selected','task.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO redaction_profiles(id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at) VALUES('profile','tenant','Public','{}','{}','redaction.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO customer_security_packages(id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at) VALUES('package','tenant','product','release','profile','private-title-marker','generated','{}','sha256:fixture','2026-10-05T00:00:00Z','package.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES('review_source','tenant','product','release','security_review','private-title-marker','test','2026-10-01T00:00:00Z','evidence.v1','sha256:fixture','sha256:fixture','json','L2','pending')`,
		`INSERT INTO manual_security_documents(id,tenant_id,product_id,release_id,document_type,title,sensitivity,evidence_id,payload_hash,schema_version,created_at) VALUES('review','tenant','product','release','security_review','private-title-marker','private','review_source','sha256:fixture','manual.v1','2026-10-01T00:00:00Z')`,
		`INSERT INTO approval_records(id,tenant_id,subject_type,subject_id,decision,reason,approver_id,schema_version,created_at) VALUES('approval_diff','tenant','contract_diff','diff_selected','approve','private-reason-marker','private-approver-marker','approval.v1','2026-10-01T00:00:00Z'),('approval_package','tenant','customer_package','package','approve','private-reason-marker','private-approver-marker','approval.v1','2026-10-01T00:00:00Z'),('approval_review','tenant','security_review','review','approve','private-reason-marker','private-approver-marker','approval.v1','2026-10-01T00:00:00Z')`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	refs := []map[string]any{{"type": "approval", "id": "approval_release"}, {"type": "approval", "id": "approval_other_kind"}, {"type": "approval", "id": "approval_diff"}, {"type": "approval", "id": "approval_package"}, {"type": "approval", "id": "approval_review"}, {"type": "exception", "id": "exception_release"}, {"type": "waiver", "id": "waiver_product"}, {"type": "release_bundle", "id": "bundle"}, {"type": "incident", "id": "incident"}, {"type": "remediation_task", "id": "task"}}
	body, err := json.Marshal(refs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE vulnerability_decisions SET supporting_refs=$1 WHERE id='decision_selected'`, body); err != nil {
		t.Fatal(err)
	}
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	v, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.Decisions) != 1 || !reflect.DeepEqual(v.Decisions[0]["supporting_refs"], refs) || tx.privateFound {
		t.Fatalf("owned support kinds result=%#v private=%v err=%v", v.Decisions, tx.privateFound, err)
	}
	for _, tc := range []struct{ name, sql, restore string }{
		{"approval to waiver", `UPDATE waivers SET scope_id='sibling_release' WHERE id='waiver_release'`, `UPDATE waivers SET scope_id='release' WHERE id='waiver_release'`},
		{"approval to diff", `UPDATE contract_diffs SET base_contract_id='openapi_contract_foreign' WHERE id='diff_selected'`, `UPDATE contract_diffs SET base_contract_id='openapi_contract_unreleased' WHERE id='diff_selected'`},
		{"approval to package", `UPDATE customer_security_packages SET product_id='sibling' WHERE id='package'`, `UPDATE customer_security_packages SET product_id='product' WHERE id='package'`},
		{"approval to review", `UPDATE evidence_items SET product_id='sibling' WHERE id='review_source'`, `UPDATE evidence_items SET product_id='product' WHERE id='review_source'`},
		{"exception", `UPDATE exceptions SET release_id='sibling_release' WHERE id='exception_release'`, `UPDATE exceptions SET release_id='release' WHERE id='exception_release'`},
		{"waiver", `UPDATE waivers SET scope_id='sibling' WHERE id='waiver_product'`, `UPDATE waivers SET scope_id='product' WHERE id='waiver_product'`},
		{"bundle", `UPDATE release_bundles SET release_id='sibling_release' WHERE id='bundle'`, `UPDATE release_bundles SET release_id='release' WHERE id='bundle'`},
		{"incident", `UPDATE incidents SET product_id='sibling' WHERE id='incident'`, `UPDATE incidents SET product_id='product' WHERE id='incident'`},
		{"task", `UPDATE remediation_tasks SET evidence_id='ev_sibling' WHERE id='task'`, `UPDATE remediation_tasks SET evidence_id='ev_selected' WHERE id='task'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.sql, tc.restore)
			tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
			v, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v.Decisions) != 0 || tx.privateFound {
				t.Fatalf("cross-scope support reference: %#v private=%v err=%v", v.Decisions, tx.privateFound, err)
			}
		})
	}
	// Every reference kind must be resolved, not merely treated as a public ID.
	for _, ref := range refs {
		t.Run(ref["type"].(string)+"_"+ref["id"].(string), func(t *testing.T) {
			invalid, err := json.Marshal([]map[string]any{{"type": ref["type"], "id": "missing"}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.pool.Exec(t.Context(), `UPDATE vulnerability_decisions SET supporting_refs=$1 WHERE id='decision_selected'`, invalid); err != nil {
				t.Fatal(err)
			}
			v, err := readCustomerPackageGovernanceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v.Decisions) != 0 {
				t.Fatalf("unowned reference kind accepted: %#v err=%v", v.Decisions, err)
			}
		})
	}
}

func TestCustomerPackageGovernanceSnapshotSkipsDisabledDecisionType(t *testing.T) {
	s := customerGovernanceFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE vulnerability_decisions SET supporting_refs='{"token":"private-disabled-marker"}' WHERE id='decision_selected'`); err != nil {
		t.Fatal(err)
	}
	profile := customerGovernanceProfile()
	profile.AllowedTypes = []string{"sbom"}
	tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
	v, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", profile, customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || v.Decisions != nil || len(v.Approvals) != 2 || tx.privateFound {
		t.Fatalf("disabled decisions must not be read: value=%#v private=%v err=%v", v, tx.privateFound, err)
	}
}

func TestCustomerPackageGovernanceSnapshotRejectsIncoherentDecisionParents(t *testing.T) {
	s := customerGovernanceFixture(t)
	for _, tc := range []struct{ name, sql, restore string }{
		{"source tenant", `UPDATE evidence_items SET tenant_id='foreign_tenant' WHERE id='source_selected_vulnerability_scan'`, `UPDATE evidence_items SET tenant_id='tenant' WHERE id='source_selected_vulnerability_scan'`},
		{"source product", `UPDATE evidence_items SET product_id='sibling' WHERE id='source_selected_vulnerability_scan'`, `UPDATE evidence_items SET product_id='product' WHERE id='source_selected_vulnerability_scan'`},
		{"source type", `UPDATE evidence_items SET type='document' WHERE id='source_selected_vulnerability_scan'`, `UPDATE evidence_items SET type='vulnerability_scan' WHERE id='source_selected_vulnerability_scan'`},
		{"source release", `UPDATE evidence_items SET release_id='sibling_release' WHERE id='source_selected_vulnerability_scan'`, `UPDATE evidence_items SET release_id='release' WHERE id='source_selected_vulnerability_scan'`},
		{"missing finding", `UPDATE vulnerability_scans SET findings='[]' WHERE id='vulnerability_scan_selected'`, `UPDATE vulnerability_scans SET findings='[{"id":"finding_selected","vulnerability":"CVE-1"}]' WHERE id='vulnerability_scan_selected'`},
		{"different vulnerability", `UPDATE vulnerability_scans SET findings='[{"id":"finding_selected","vulnerability":"CVE-OTHER"}]' WHERE id='vulnerability_scan_selected'`, `UPDATE vulnerability_scans SET findings='[{"id":"finding_selected","vulnerability":"CVE-1"}]' WHERE id='vulnerability_scan_selected'`},
		{"ambiguous finding", `UPDATE vulnerability_scans SET findings='[{"id":"finding_selected","vulnerability":"CVE-1"},{"id":"finding_selected","vulnerability":"CVE-1"}]' WHERE id='vulnerability_scan_selected'`, `UPDATE vulnerability_scans SET findings='[{"id":"finding_selected","vulnerability":"CVE-1"}]' WHERE id='vulnerability_scan_selected'`},
		{"sibling evidence", `UPDATE vulnerability_decisions SET evidence_id='ev_sibling' WHERE id='decision_selected'`, `UPDATE vulnerability_decisions SET evidence_id='ev_selected' WHERE id='decision_selected'`},
		{"foreign evidence list", `UPDATE vulnerability_decisions SET evidence_ids=ARRAY['ev_foreign'] WHERE id='decision_selected'`, `UPDATE vulnerability_decisions SET evidence_ids=ARRAY['ev_selected'] WHERE id='decision_selected'`},
		{"sibling SBOM", `UPDATE vulnerability_decisions SET sbom_id='sbom_sibling' WHERE id='decision_selected'`, `UPDATE vulnerability_decisions SET sbom_id='sbom_selected' WHERE id='decision_selected'`},
		{"foreign VEX", `UPDATE vulnerability_decisions SET vex_document_id='vex_foreign' WHERE id='decision_selected'`, `UPDATE vulnerability_decisions SET vex_document_id='vex_selected' WHERE id='decision_selected'`},
		{"sibling supporting approval", `UPDATE approval_records SET subject_id='sibling_release' WHERE id='approval_release'`, `UPDATE approval_records SET subject_id='release' WHERE id='approval_release'`},
		{"foreign supporting evidence", `UPDATE approval_records SET evidence_id='ev_foreign' WHERE id='approval_release'`, `UPDATE approval_records SET evidence_id='ev_selected' WHERE id='approval_release'`},
		{"legacy supersession", `UPDATE vulnerability_decisions SET superseded_by='replacement' WHERE id='decision_selected'`, `UPDATE vulnerability_decisions SET superseded_by=NULL WHERE id='decision_selected'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.sql, tc.restore)
			tx := &customerMetadataWatchTx{Tx: customerCatalogReadTx(t, s)}
			v, err := readCustomerPackageGovernanceTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v.Decisions) != 0 || tx.privateFound {
				t.Fatalf("incoherent decision parents: %#v private=%v err=%v", v.Decisions, tx.privateFound, err)
			}
		})
	}
}

func TestCustomerPackageGovernanceSnapshotUsesAppendOnlyDecisionSupersession(t *testing.T) {
	s := customerGovernanceFixture(t)
	if _, err := s.pool.Exec(t.Context(), `BEGIN;
	 INSERT INTO vulnerability_decision_supersessions(tenant_id,finding_id,predecessor_id,successor_id,created_at,schema_version)
	 VALUES('tenant','finding_selected','decision_selected','replacement','2026-10-03T00:00:00Z','decision-supersession.v1');
	 INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,source,customer_visible,supersedes,schema_version,created_at)
	 VALUES('replacement','tenant','finding_selected','vulnerability_scan_selected','release','CVE-1','affected','reviewed','manual',true,'decision_selected','decision.v1','2026-10-03T00:00:00Z'); COMMIT`); err != nil {
		t.Fatal(err)
	}
	v, err := readCustomerPackageGovernanceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.Decisions) != 1 || v.Decisions[0]["id"] != "replacement" {
		t.Fatalf("append-only supersession ignored: %#v err=%v", v.Decisions, err)
	}
	var unchanged bool
	if err := s.pool.QueryRow(t.Context(), `SELECT superseded_by IS NULL AND internal_notes='private-notes-marker' FROM vulnerability_decisions WHERE id='decision_selected'`).Scan(&unchanged); err != nil || !unchanged {
		t.Fatalf("historical decision was modified=%v err=%v", !unchanged, err)
	}
}

func TestCustomerPackageGovernanceSnapshotDoesNotWaitForWriterFence(t *testing.T) {
	s := customerGovernanceFixture(t)
	writer, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Rollback(context.WithoutCancel(t.Context())) })
	if err := coordination.LockWorkerProjection(t.Context(), writer, "tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(t.Context(), `SELECT id FROM releases WHERE id='release' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	v, err := readCustomerPackageGovernanceTx(ctx, customerCatalogReadTx(t, s), "tenant", "product", "release", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.Decisions) != 1 || len(v.Approvals) != 2 || len(v.Exceptions) != 1 {
		t.Fatalf("reader blocked by active command fence/locks: %#v err=%v", v, err)
	}
}

func TestCustomerPackageGovernanceSnapshotScopesLegacyUnreleasedDecisions(t *testing.T) {
	s := customerGovernanceFixture(t)
	for _, suffix := range []string{"unreleased", "sibling_unreleased"} {
		if _, err := s.pool.Exec(t.Context(), `UPDATE vulnerability_scans SET findings=jsonb_build_array(jsonb_build_object('id',$1::text,'vulnerability','CVE-1')) WHERE id=$2`, "finding_"+suffix, "vulnerability_scan_"+suffix); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pool.Exec(t.Context(), `INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,vulnerability,status,justification,source,customer_visible,schema_version,created_at) VALUES($1,'tenant',$2,$3,'CVE-1','affected','reviewed','manual',true,'decision.v1','2026-10-01T00:00:00Z')`, "decision_"+suffix, "finding_"+suffix, "vulnerability_scan_"+suffix); err != nil {
			t.Fatal(err)
		}
	}
	v, err := readCustomerPackageGovernanceTx(t.Context(), customerCatalogReadTx(t, s), "tenant", "product", "", customerGovernanceProfile(), customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(v.Decisions) != 1 || v.Decisions[0]["id"] != "decision_unreleased" || v.Decisions[0]["release_id"] != "" {
		t.Fatalf("legacy unreleased decision product scope: %#v err=%v", v.Decisions, err)
	}
}
