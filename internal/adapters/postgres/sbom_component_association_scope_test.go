package postgres

import (
	"errors"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestPostgresSBOMComponentsFilterIncoherentArtifactAssociationsBeforePaging(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	statements := []string{
		`INSERT INTO tenants(id,name) VALUES('tenant','Tenant')`,
		`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Product','product')`,
		`INSERT INTO projects(id,tenant_id,product_id,name) VALUES('project','tenant','product','Project')`,
		`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1','draft'),('other-release','tenant','product','2','draft')`,
		`INSERT INTO artifacts(id,tenant_id,name,media_type,size,digest) VALUES('artifact','tenant','Artifact','application/octet-stream',1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`,
		`INSERT INTO evidence_items(id,tenant_id,product_id,release_id,type,title,source_system,observed_at,evidence_version,schema_version,payload_hash,canonical_hash,canonicalization,subject_refs,trust_level,verification_status)
		 VALUES('source','tenant','product','release','sbom','SBOM','test',now(),1,'v1','hash','hash','canonical-json.v1','[{"type":"artifact","id":"artifact"}]','L2','pending')`,
		`INSERT INTO sboms(id,tenant_id,evidence_id,release_id,artifact_id,format,spec_version,component_count,components)
		 VALUES('sbom','tenant','source','release','artifact','cyclonedx','1.6',1,'[{"identity":"component","name":"api","version":"1","purl":"pkg:generic/api@1"}]')`,
	}
	for _, statement := range statements {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	query, err := evidencequery.NewSBOMComponents(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "reader", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:read"}}}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	for _, association := range []struct{ name, insert, correct, remove string }{
		{"evidence", `INSERT INTO evidence_items(id,tenant_id,project_id,release_id,type,title,source_system,observed_at,evidence_version,schema_version,payload_hash,canonical_hash,canonicalization,subject_refs,trust_level,verification_status)
		 VALUES('association','tenant','project','other-release','document','Association','test',now(),1,'v1','hash','hash','canonical-json.v1','[{"type":"artifact","id":"artifact"}]','L2','pending')`, `UPDATE evidence_items SET release_id='release' WHERE id='association'`, `DELETE FROM evidence_items WHERE id='association'`},
		{"build", `INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version)
		 VALUES('build','tenant','project','other-release','test','commit','passed',now(),'[{"artifact_id":"artifact","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]','v1')`, `UPDATE build_runs SET release_id='release' WHERE id='build'`, `DELETE FROM build_runs WHERE id='build'`},
	} {
		t.Run(association.name, func(t *testing.T) {
			if _, err := store.pool.Exec(ctx, association.insert); err != nil {
				t.Fatal(err)
			}
			collection, err := query.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{}, page, nil)
			if err != nil || len(collection.Items) != 0 || collection.Next != nil {
				t.Error("incoherent release association reached the selected page", collection, err)
			}
			point, err := query.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom"}, page, nil)
			if !errors.Is(err, evidencequery.ErrNotFound) || len(point.Items) != 0 || point.Next != nil {
				t.Error("incoherent association was not masked before paging", point, err)
			}
			if _, err := store.pool.Exec(ctx, association.correct); err != nil {
				t.Fatal(err)
			}
			point, err = query.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom"}, page, nil)
			if err != nil || len(point.Items) != 1 || point.Items[0].ID != "sbom:0" || point.Items[0].ReleaseID != "release" || point.Items[0].ArtifactID != "artifact" || point.Items[0].Component.PURL != "pkg:generic/api@1" || point.Next != nil {
				t.Error("coherent current association lost component metadata", point, err)
			}
			if _, err := store.pool.Exec(ctx, association.remove); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := store.pool.Exec(ctx, `UPDATE evidence_items SET project_id='project' WHERE id='source'`); err != nil {
		t.Fatal(err)
	}
	visible, err := query.ListPage(ctx, actor, evidencequery.SBOMComponentFilter{SBOMID: "sbom"}, page, nil)
	if err != nil || len(visible.Items) != 1 || visible.Items[0].ID != "sbom:0" || visible.Items[0].Component.PURL != "pkg:generic/api@1" {
		t.Fatal("coherent source association lost visibility", visible, err)
	}
}
