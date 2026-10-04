package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func readinessScopeFixture(t *testing.T) *Store {
	t.Helper()
	s := customerCatalogFixture(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, sql := range []string{
		`DELETE FROM sboms; DELETE FROM vex_documents; DELETE FROM evidence_items; DELETE FROM build_runs`,
		`INSERT INTO collectors(id,tenant_id,name,type,version,api_key_id,status,allowed_scopes,schema_version) VALUES('collector','tenant','CI','generic_ci','1','key','active','[]','collector.v1'),('foreign_collector','foreign_tenant','Foreign','generic_ci','1','key','active','[]','collector.v1')`,
		`INSERT INTO build_runs(id,tenant_id,project_id,release_id,collector_id,provider,commit_sha,started_at,status,outputs,schema_version) VALUES('build','tenant','project','release','collector','test','commit',now(),'passed','[{"artifact_id":"artifact_build","digest":"` + digest + `"}]','build.v1')`,
		`UPDATE artifacts SET digest='` + digest + `' WHERE id='artifact_build'`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,build_id,type,title,source_system,observed_at,schema_version,payload_hash,payload_size,canonical_hash,canonicalization,trust_level,verification_status,payload_ref,subject_refs) VALUES
		 ('sbom_source','tenant','product','project','release',NULL,'sbom','SBOM','test',now(),'evidence.v1','sha256:source',7,'sha256:source','json','L2','pending',NULL,'[{"type":"artifact","id":"artifact_build"}]'),
		 ('scan_source','tenant','product','project','release',NULL,'vulnerability_scan','Scan','test',now(),'evidence.v1','sha256:source',7,'sha256:source','json','L2','pending',NULL,'[]'),
		 ('attestation_source','tenant','product','project','release','build','build_attestation','Attestation','test',now(),'evidence.v1','sha256:source',7,'sha256:source','json','L2','pending','private-payload-marker','[]')`,
		`INSERT INTO build_attestations(id,tenant_id,build_id,evidence_id,payload_ref,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version) VALUES('attestation','tenant','build','attestation_source','private-payload-marker','sha256:source',7,'application/json','test','["` + digest + `"]',0,1,'passed','attestation.v1')`,
		`INSERT INTO verification_results(id,tenant_id,subject_type,subject_id,result,checks,verified_at,assurance_profile,schema_version) VALUES('receipt','tenant','build_attestation','attestation','passed','[]',now(),'{"id":"dsse-attestation-signature.v1"}','verification-result.v2.0.0')`,
		`INSERT INTO vulnerability_scans(id,tenant_id,evidence_id,release_id,scanner,target_ref,summary,findings) VALUES('scan','tenant','scan_source','release','test','target','{}','[{"id":"finding","vulnerability":"CVE-1","component":"pkg:one","severity":"critical","state":"open"}]')`,
		`INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,release_id,vulnerability,component,status,justification,impact_statement,customer_visible,source,schema_version,created_at) VALUES('decision','tenant','finding','scan','release','CVE-1','pkg:one','not_affected','reviewed','reviewed',true,'manual','decision.v1','2026-10-01T00:00:00Z')`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestReadinessPresenceRequiresCoherentEvidenceBuildAndAttestationParents(t *testing.T) {
	s := readinessScopeFixture(t)
	valid, err := s.ReadReleaseReadinessSnapshot(t.Context(), "tenant", "release")
	if err != nil || !valid.HasArtifact || !valid.HasArtifactDigest || !valid.HasSBOM || !valid.HasVulnerabilityScan || !valid.HasPassedBuild || !valid.HasVerifiedBuildAttestation || valid.UnhandledCritical {
		t.Fatal("valid scoped facts lost", valid, err)
	}
	for _, tc := range []struct {
		name, change, restore                    string
		artifact, sbom, scan, build, attestation bool
	}{
		{"sibling evidence product", `UPDATE evidence_items SET product_id='sibling' WHERE id='sbom_source'`, `UPDATE evidence_items SET product_id='product' WHERE id='sbom_source'`, true, true, false, true, true},
		{"foreign evidence tenant", `UPDATE evidence_items SET tenant_id='foreign_tenant' WHERE id='sbom_source'`, `UPDATE evidence_items SET tenant_id='tenant' WHERE id='sbom_source'`, true, true, false, true, true},
		{"sibling evidence project", `UPDATE evidence_items SET project_id='sibling_project' WHERE id='sbom_source'`, `UPDATE evidence_items SET project_id='project' WHERE id='sbom_source'`, true, true, false, true, true},
		{"sibling scan product", `UPDATE evidence_items SET product_id='sibling' WHERE id='scan_source'`, `UPDATE evidence_items SET product_id='product' WHERE id='scan_source'`, false, false, true, false, false},
		{"sibling build project", `UPDATE build_runs SET project_id='sibling_project' WHERE id='build'`, `UPDATE build_runs SET project_id='project' WHERE id='build'`, false, false, false, true, true},
		{"foreign build collector", `UPDATE build_runs SET collector_id='foreign_collector' WHERE id='build'`, `UPDATE build_runs SET collector_id='collector' WHERE id='build'`, false, false, false, true, true},
		{"wrong registered output", `UPDATE build_runs SET outputs=jsonb_build_array(jsonb_build_object('artifact_id','artifact_wrong_digest','digest',(SELECT digest FROM artifacts WHERE id='artifact_build'))) WHERE id='build'`, `UPDATE build_runs SET outputs=jsonb_build_array(jsonb_build_object('artifact_id','artifact_build','digest',(SELECT digest FROM artifacts WHERE id='artifact_build'))) WHERE id='build'`, false, false, false, true, true},
		{"wrong source type", `UPDATE evidence_items SET type='sbom' WHERE id='attestation_source'`, `UPDATE evidence_items SET type='build_attestation' WHERE id='attestation_source'`, false, false, false, false, true},
		{"foreign attestation source", `UPDATE evidence_items SET tenant_id='foreign_tenant' WHERE id='attestation_source'`, `UPDATE evidence_items SET tenant_id='tenant' WHERE id='attestation_source'`, false, false, false, false, true},
		{"sibling attestation source", `UPDATE evidence_items SET product_id='sibling' WHERE id='attestation_source'`, `UPDATE evidence_items SET product_id='product' WHERE id='attestation_source'`, false, false, false, false, true},
		{"unbound attestation source", `UPDATE evidence_items SET build_id=NULL WHERE id='attestation_source'`, `UPDATE evidence_items SET build_id='build' WHERE id='attestation_source'`, false, false, false, false, true},
		{"wrong source digest", `UPDATE evidence_items SET payload_hash='sha256:other' WHERE id='attestation_source'`, `UPDATE evidence_items SET payload_hash='sha256:source' WHERE id='attestation_source'`, false, false, false, false, true},
		{"wrong source size", `UPDATE evidence_items SET payload_size=8 WHERE id='attestation_source'`, `UPDATE evidence_items SET payload_size=7 WHERE id='attestation_source'`, false, false, false, false, true},
		{"wrong source reference", `UPDATE evidence_items SET payload_ref='private-other-marker' WHERE id='attestation_source'`, `UPDATE evidence_items SET payload_ref='private-payload-marker' WHERE id='attestation_source'`, false, false, false, false, true},
		{"wrong receipt tenant", `UPDATE verification_results SET tenant_id='foreign_tenant' WHERE id='receipt'`, `UPDATE verification_results SET tenant_id='tenant' WHERE id='receipt'`, false, false, false, false, true},
		{"wrong receipt profile", `UPDATE verification_results SET assurance_profile='{"id":"other"}' WHERE id='receipt'`, `UPDATE verification_results SET assurance_profile='{"id":"dsse-attestation-signature.v1"}' WHERE id='receipt'`, false, false, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.change, tc.restore)
			v, err := s.ReadReleaseReadinessSnapshot(t.Context(), "tenant", "release")
			if err != nil || v.HasArtifact == tc.artifact || v.HasArtifactDigest == tc.artifact || v.HasSBOM == tc.sbom || v.HasVulnerabilityScan == tc.scan || v.HasPassedBuild == tc.build || v.HasVerifiedBuildAttestation == tc.attestation {
				t.Fatal("incoherent parents contributed readiness", v, err)
			}
		})
	}
}

func TestReadinessScopeReachesPublicPackageChecksWithoutWriting(t *testing.T) {
	s := readinessScopeFixture(t)
	if _, err := s.pool.Exec(t.Context(), `UPDATE build_runs SET collector_id='foreign_collector' WHERE id='build'; UPDATE vulnerability_decisions SET component='pkg:other' WHERE id='decision'`); err != nil {
		t.Fatal(err)
	}
	tx := customerCatalogReadTx(t, s)
	checks, err := readCustomerPackageReadinessTx(t.Context(), tx, "tenant", "product", "release", customerGovernanceNow, &customerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"release_requires_passed_build", "release_requires_build_attestation", "critical_exploitable_blocks_release"} {
		if v := readinessCheck(t, checks, name); v.Result != "failed" {
			t.Fatal("incoherent facts granted public package assurance", v)
		}
	}
	var effects int
	if err := tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM policy_evaluations)+(SELECT count(*) FROM audit_chain_entries)+(SELECT count(*) FROM outbox_jobs)`).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("readiness inspection persisted effects", effects, err)
	}
}

func TestReadinessHandlingAndMissingIDsRequireCurrentFindingIdentity(t *testing.T) {
	s := readinessScopeFixture(t)
	for _, tc := range []struct{ name, change, restore string }{
		{"wrong vulnerability", `UPDATE vulnerability_decisions SET vulnerability='CVE-other',impact_statement='',justification='' WHERE id='decision'`, `UPDATE vulnerability_decisions SET vulnerability='CVE-1',impact_statement='reviewed',justification='reviewed' WHERE id='decision'`},
		{"wrong component", `UPDATE vulnerability_decisions SET component='pkg:other',impact_statement='',justification='' WHERE id='decision'`, `UPDATE vulnerability_decisions SET component='pkg:one',impact_statement='reviewed',justification='reviewed' WHERE id='decision'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutateCustomerGovernanceFixture(t, s, tc.change, tc.restore)
			v, err := s.ReadReleaseReadinessSnapshot(t.Context(), "tenant", "release")
			if err != nil || !v.UnhandledCritical || len(v.MissingCustomerStatementIDs) != 0 || len(v.MissingNotAffectedReasonIDs) != 0 {
				t.Fatal("unrelated decision cleared risk or leaked missing IDs", v, err)
			}
		})
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE vulnerability_decisions SET superseded_by='unrelated_latest' WHERE id='decision'; INSERT INTO vulnerability_decisions(id,tenant_id,finding_id,scan_id,release_id,vulnerability,component,status,justification,source,schema_version,created_at) VALUES('unrelated_latest','tenant','finding','scan','release','CVE-other','pkg:one','not_affected','reviewed','manual','decision.v1','2026-10-02T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	v, err := s.ReadReleaseReadinessSnapshot(t.Context(), "tenant", "release")
	if err != nil || !v.UnhandledCritical {
		t.Fatal("unrelated successor inherited historical handling", v, err)
	}
}

func TestReadinessIgnoresOutOfScopeParsedSourcesAndExceptionReferences(t *testing.T) {
	s := readinessScopeFixture(t)
	for _, sql := range []string{
		`UPDATE vulnerability_decisions SET impact_statement='',justification='' WHERE id='decision'`,
		`UPDATE evidence_items SET product_id='sibling' WHERE id='scan_source'`,
	} {
		if _, err := s.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	v, err := s.ReadReleaseReadinessSnapshot(t.Context(), "tenant", "release")
	if err != nil || v.HasVulnerabilityScan || v.UnhandledCritical || len(v.MissingCustomerStatementIDs) != 0 || len(v.MissingNotAffectedReasonIDs) != 0 {
		t.Fatal("out-of-scope parsed source influenced release", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE vulnerability_scans SET findings='{}' WHERE id='scan'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadReleaseReadinessSnapshot(t.Context(), "tenant", "release"); err != nil {
		t.Fatal("malformed unrelated scan blocked selected release", err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE evidence_items SET product_id='product' WHERE id='scan_source'; UPDATE vulnerability_scans SET findings='[{"id":"finding","vulnerability":"CVE-1","component":"pkg:one","severity":"critical","state":"open"}]'; UPDATE vulnerability_decisions SET status='affected' WHERE id='decision'; INSERT INTO exceptions(id,tenant_id,release_id,control_id,reason,owner,expires_at,approved,approved_by,approved_at) VALUES('exception','tenant','release','missing-control','','',now()+interval '1 hour',true,'reviewer',now())`); err != nil {
		t.Fatal(err)
	}
	v, err = s.ReadReleaseReadinessSnapshot(t.Context(), "tenant", "release")
	if err != nil || !v.UnhandledCritical || len(v.IncompleteExceptionIDs) != 0 {
		t.Fatal("incoherent exception control cleared risk or contributed IDs", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE exceptions SET control_id=NULL,finding_id='unrelated-finding' WHERE id='exception'`); err != nil {
		t.Fatal(err)
	}
	v, err = s.ReadReleaseReadinessSnapshot(t.Context(), "tenant", "release")
	if err != nil || !v.UnhandledCritical || len(v.IncompleteExceptionIDs) != 0 {
		t.Fatal("unrelated exception finding influenced selected release", v, err)
	}
	if _, err := s.pool.Exec(t.Context(), `UPDATE exceptions SET finding_id='finding' WHERE id='exception'`); err != nil {
		t.Fatal(err)
	}
	v, err = s.ReadReleaseReadinessSnapshot(t.Context(), "tenant", "release")
	if err != nil || v.UnhandledCritical || len(v.IncompleteExceptionIDs) != 1 || v.IncompleteExceptionIDs[0] != "exception" {
		t.Fatal("coherent exception lost existing policy semantics", v, err)
	}
}

func TestReadinessScopeReadsDoNotTakeWriterFence(t *testing.T) {
	s := readinessScopeFixture(t)
	writer, err := s.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(t.Context()) }()
	if err := coordination.LockWorkerProjection(t.Context(), writer, "tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(t.Context(), `SELECT id FROM releases WHERE id='release' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	v, err := s.ReadReleaseReadinessSnapshot(ctx, "tenant", "release")
	if err != nil || !v.HasVerifiedBuildAttestation || v.UnhandledCritical {
		t.Fatal("scoped read blocked or lost committed facts", v, err)
	}
}
