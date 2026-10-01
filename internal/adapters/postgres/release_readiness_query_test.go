package postgres

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func TestReadReleaseReadinessSnapshotUsesScopedTrustedFacts(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants (id,name) VALUES ('ten_ready','Ready'),('ten_other','Other')`)
	exec(`INSERT INTO products (id,tenant_id,name,slug) VALUES ('prod_ready','ten_ready','Ready','ready'),('prod_other','ten_other','Other','other')`)
	exec(`INSERT INTO projects (id,tenant_id,product_id,name) VALUES ('proj_ready','ten_ready','prod_ready','Ready')`)
	exec(`INSERT INTO releases (id,tenant_id,product_id,version,state) VALUES ('rel_ready','ten_ready','prod_ready','1','draft'),('rel_other','ten_other','prod_other','1','draft')`)
	if _, err := store.ReadReleaseReadinessSnapshot(ctx, "ten_ready", "rel_other"); !errors.Is(err, riskapp.ErrNotFound) {
		t.Fatalf("foreign release: %v", err)
	}
	exec(`INSERT INTO evidence_items (id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,subject_refs)
		VALUES ('ev_ready','ten_ready','prod_ready','rel_ready','sbom','Ready','test',$1,'evidence.v1','sha256:test','sha256:test','json','L2','pending','[{"type":"artifact","id":"art_ready"}]')`, now)
	exec(`INSERT INTO evidence_items (id,tenant_id,product_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)
		VALUES ('ev_scan','ten_ready','prod_ready','rel_ready','vulnerability_scan','Ready','test',$1,'evidence.v1','sha256:test','sha256:test','json','L2','pending')`, now)
	snapshot, err := store.ReadReleaseReadinessSnapshot(ctx, "ten_ready", "rel_ready")
	if err != nil || !snapshot.HasArtifact || !snapshot.HasSBOM || snapshot.HasArtifactDigest || snapshot.HasPassedBuild || snapshot.HasVerifiedSignedBundle {
		t.Fatalf("unregistered artifact snapshot=%#v err=%v", snapshot, err)
	}
	exec(`INSERT INTO artifacts (id,tenant_id,name,media_type,size,digest) VALUES ('art_ready','ten_ready','ready','application/octet-stream',1,$1)`, digest)
	exec(`INSERT INTO build_runs (id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version)
		VALUES ('build_ready','ten_ready','proj_ready','rel_ready','test','abc','passed',$1,$2,'build.v1')`, now, `[ {"digest":"`+digest+`"} ]`)
	exec(`INSERT INTO build_attestations (id,tenant_id,build_id,evidence_id,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version)
		VALUES ('att_ready','ten_ready','build_ready','ev_ready','sha256:test',1,'application/json','test',$1,0,1,'passed','att.v1')`, `["`+digest+`"]`)
	exec(`INSERT INTO verification_results (id,tenant_id,subject_type,subject_id,result,checks,verified_at,assurance_profile,schema_version)
		VALUES ('vr_ready','ten_ready','build_attestation','att_ready','passed','[]',$1,'{"id":"dsse-attestation-signature.v1"}','verification-result.v2.0.0')`, now)
	exec(`INSERT INTO vulnerability_scans (id,tenant_id,evidence_id,release_id,scanner,target_ref,summary,findings)
		VALUES ('scan_ready','ten_ready','ev_scan','rel_ready','test','target','{}','[{"id":"finding_ready","severity":"critical","state":"open"},{"id":"finding_critical","severity":"critical","state":"open"},{"id":"finding_high","severity":"high","state":"open"}]')`)
	exec(`INSERT INTO vulnerability_decisions (id,tenant_id,finding_id,scan_id,release_id,vulnerability,status,justification,source,schema_version,customer_visible)
		VALUES ('decision_ready','ten_ready','finding_ready','scan_ready','rel_ready','CVE-1','not_affected','','manual','decision.v1',true)`)
	exec(`INSERT INTO exceptions (id,tenant_id,release_id,reason,owner,expires_at,approved) VALUES ('ex_ready','ten_ready','rel_ready','','',$1,false)`, now.Add(time.Hour))
	exec(`INSERT INTO redaction_profiles (id,tenant_id,name,allowed_types,excluded_fields,schema_version,created_at) VALUES ('profile_ready','ten_ready','Ready',ARRAY['sbom'],ARRAY['payload_ref','object_key','private_key','token','secret','internal_notes'],'profile.v1',$1)`, now)
	exec(`INSERT INTO customer_security_packages (id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at)
		VALUES ('package_ready','ten_ready','prod_ready','rel_ready','profile_ready','Ready','generated','{}','sha256:test',$1,'package.v1',$2)`, now.Add(time.Hour), now)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestHash := "sha256:manifest"
	exec(`INSERT INTO signing_keys (id,tenant_id,kid,algorithm,status,public_key,valid_from) VALUES ('key_ready','ten_ready','kid','Ed25519','active',$1,$2)`, base64.RawStdEncoding.EncodeToString(public), now.Add(-time.Hour))
	exec(`INSERT INTO signatures (id,tenant_id,subject_type,subject_id,key_id,algorithm,value,created_at) VALUES ('sig_ready','ten_ready','release_bundle','bundle_ready','key_ready','Ed25519',$1,$2)`, base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte(manifestHash))), now)
	exec(`INSERT INTO release_bundles (id,tenant_id,release_id,state,manifest,manifest_hash,signature_refs) VALUES ('bundle_ready','ten_ready','rel_ready','generated','{}',$1,'["sig_ready"]')`, manifestHash)
	snapshot, err = store.ReadReleaseReadinessSnapshot(ctx, "ten_ready", "rel_ready")
	if err != nil || snapshot.TenantID != "ten_ready" || snapshot.ProductID != "prod_ready" || snapshot.ReleaseID != "rel_ready" || !snapshot.HasArtifact || !snapshot.HasSBOM || !snapshot.HasVulnerabilityScan || !snapshot.HasArtifactDigest || !snapshot.HasPassedBuild || !snapshot.HasVerifiedBuildAttestation || !snapshot.HasVerifiedSignedBundle || !snapshot.UnhandledCritical || !snapshot.UnhandledHigh || snapshot.PackageCount != 1 || len(snapshot.InvalidPackageOrProfileIDs) != 0 || len(snapshot.IncompleteExceptionIDs) != 1 || snapshot.IncompleteExceptionIDs[0] != "ex_ready" || len(snapshot.MissingCustomerStatementIDs) != 1 || snapshot.MissingCustomerStatementIDs[0] != "decision_ready" || len(snapshot.MissingNotAffectedReasonIDs) != 1 || snapshot.MissingNotAffectedReasonIDs[0] != "decision_ready" {
		t.Fatalf("readiness snapshot=%#v err=%v", snapshot, err)
	}
	exec(`UPDATE vulnerability_decisions SET justification='triaged',impact_statement='not affected' WHERE id='decision_ready'`)
	exec(`INSERT INTO exceptions (id,tenant_id,release_id,reason,owner,expires_at,approved,approved_by,approved_at) VALUES ('ex_all','ten_ready','rel_ready','approved','reviewer',$1,true,'reviewer',$2)`, now.Add(time.Hour), now)
	snapshot, err = store.ReadReleaseReadinessSnapshot(ctx, "ten_ready", "rel_ready")
	if err != nil || snapshot.UnhandledCritical || snapshot.UnhandledHigh || len(snapshot.MissingCustomerStatementIDs) != 0 || len(snapshot.MissingNotAffectedReasonIDs) != 0 {
		t.Fatalf("handled finding snapshot=%#v err=%v", snapshot, err)
	}
	readiness, err := riskquery.NewReleaseReadinessQuery(store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	reportQuery, err := packagequery.NewMissingEvidenceReport(readiness)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_ready", UserID: "user_ready", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_ready", Scopes: []string{"verify:read"}}}}
	report, err := reportQuery.Report(ctx, actor, "rel_ready")
	if err != nil || report["release_id"] != "rel_ready" || report["result"] != "failed" {
		t.Fatalf("durable report=%#v err=%v", report, err)
	}
	var evaluations int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM policy_evaluations WHERE tenant_id='ten_ready'`).Scan(&evaluations); err != nil || evaluations != 0 {
		t.Fatalf("read-only report persisted %d evaluations: %v", evaluations, err)
	}
	actor.ResourceGrants[0].ResourceID = "rel_other"
	if _, err := reportQuery.Report(ctx, actor, "rel_ready"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("foreign release grant reached readiness report: %v", err)
	}
	exec(`UPDATE signatures SET subject_id='other_bundle' WHERE id='sig_ready'`)
	snapshot, err = store.ReadReleaseReadinessSnapshot(ctx, "ten_ready", "rel_ready")
	if err != nil || snapshot.HasVerifiedSignedBundle {
		t.Fatalf("replayed signature snapshot=%#v err=%v", snapshot, err)
	}
	exec(`UPDATE signatures SET subject_id='bundle_ready' WHERE id='sig_ready'`)
	exec(`UPDATE signatures SET algorithm='other' WHERE id='sig_ready'`)
	snapshot, err = store.ReadReleaseReadinessSnapshot(ctx, "ten_ready", "rel_ready")
	if err != nil || snapshot.HasVerifiedSignedBundle {
		t.Fatalf("wrong signature algorithm snapshot=%#v err=%v", snapshot, err)
	}
	exec(`UPDATE signatures SET algorithm='Ed25519' WHERE id='sig_ready'`)
	exec(`UPDATE redaction_profiles SET excluded_fields=ARRAY['payload_ref'] WHERE id='profile_ready'`)
	snapshot, err = store.ReadReleaseReadinessSnapshot(ctx, "ten_ready", "rel_ready")
	if err != nil || len(snapshot.InvalidPackageOrProfileIDs) != 1 || snapshot.InvalidPackageOrProfileIDs[0] != "package_ready" {
		t.Fatalf("unsafe package profile snapshot=%#v err=%v", snapshot, err)
	}
	exec(`UPDATE vulnerability_decisions SET impact_statement='' WHERE id='decision_ready'`)
	exec(`UPDATE vulnerability_decisions SET id=repeat('x',1100) WHERE id='decision_ready'`)
	if result, err := store.ReadReleaseReadinessSnapshot(ctx, "ten_ready", "rel_ready"); !errors.Is(err, riskapp.ErrValidation) || result.ReleaseID != "" {
		t.Fatalf("oversized decision ID snapshot=%#v err=%v", result, err)
	}
	exec(`UPDATE vulnerability_decisions SET id='decision_ready',impact_statement='reviewed' WHERE id=repeat('x',1100)`)
	exec(`UPDATE vulnerability_scans SET findings='{}'::jsonb WHERE id='scan_ready'`)
	if result, err := store.ReadReleaseReadinessSnapshot(ctx, "ten_ready", "rel_ready"); !errors.Is(err, riskapp.ErrValidation) || result.ReleaseID != "" {
		t.Fatalf("malformed findings snapshot=%#v err=%v", result, err)
	}
}
