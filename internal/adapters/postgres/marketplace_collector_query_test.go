package postgres

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	experimentalquery "github.com/aatuh/evydence/internal/experimental/query"
)

func TestPostgresMarketplaceCollectorQueryPagesTenantRowsAndResolvesCurrentReferences(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	ctx := t.Context()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"tenant_market", "tenant_other"} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO tenants (id,name,created_at) VALUES ($1,$1,$2)`, tenant, now); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct{ id, tenant, signature, sbom, scan string }{
		{"market_a", "tenant_market", "", "", ""},
		{"market_b", "tenant_market", "sig_market", "sbom_market", "scan_market"},
		{"market_c", "tenant_market", "sig_other", "sbom_other", "scan_other"},
		{"market_other", "tenant_other", "", "", ""},
	} {
		if _, err := store.pool.Exec(ctx, `INSERT INTO marketplace_collectors (id,tenant_id,name,provider,version,publisher,manifest_hash,signature_id,sbom_id,scan_id,state,limitations,schema_version,created_at) VALUES ($1,$2,$1,'scanner',$1,'publisher','sha256:manifest',NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),'published',ARRAY['recorded metadata only'],'marketplace-collector.v1.0.0',$6)`, row.id, row.tenant, row.signature, row.sbom, row.scan, now); err != nil {
			t.Fatal(err)
		}
	}
	request := experimentalquery.MarketplaceCollectorPageRequest{TenantID: "tenant_market", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	first, err := store.PageMarketplaceCollectors(ctx, request)
	if err != nil || len(first.Items) != 1 || first.Items[0].ID != "market_a" || first.Next == nil {
		t.Fatalf("first page=%#v error=%v", first, err)
	}
	request.After = first.Next
	second, err := store.PageMarketplaceCollectors(ctx, request)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "market_b" || second.Next == nil || len(second.Items[0].Limitations) != 1 {
		t.Fatalf("second page=%#v error=%v", second, err)
	}
	request.After = second.Next
	third, err := store.PageMarketplaceCollectors(ctx, request)
	if err != nil || len(third.Items) != 1 || third.Items[0].ID != "market_c" || third.Next != nil {
		t.Fatalf("third page=%#v error=%v", third, err)
	}
	request.Page = appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Descending}
	request.After = nil
	descending, err := store.PageMarketplaceCollectors(ctx, request)
	if err != nil || len(descending.Items) != 2 || descending.Items[0].ID != "market_c" || descending.Items[1].ID != "market_b" || descending.Next == nil {
		t.Fatalf("descending page=%#v error=%v", descending, err)
	}
	request.After = descending.Next
	last, err := store.PageMarketplaceCollectors(ctx, request)
	if err != nil || len(last.Items) != 1 || last.Items[0].ID != "market_a" || last.Next != nil {
		t.Fatalf("descending continuation=%#v error=%v", last, err)
	}
	request.After = nil
	request.TenantID = "tenant_other"
	other, err := store.PageMarketplaceCollectors(ctx, request)
	if err != nil || len(other.Items) != 1 || other.Items[0].ID != "market_other" {
		t.Fatalf("other tenant page=%#v error=%v", other, err)
	}
	if _, err := store.GetMarketplaceCollectorPoint(ctx, "tenant_market", "market_other"); !errors.Is(err, experimentalquery.ErrNotFound) {
		t.Fatalf("foreign point error=%v", err)
	}
	for _, statement := range []string{
		`INSERT INTO signing_keys (id,tenant_id,kid,algorithm,status,public_key,valid_from) VALUES ('key_market','tenant_market','kid','Ed25519','active','public',now())`,
		`INSERT INTO signatures (id,tenant_id,subject_type,subject_id,key_id,algorithm,value) VALUES ('sig_market','tenant_market','collector','market_b','key_market','Ed25519','value')`,
		`INSERT INTO evidence_items (id,tenant_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ('ev_market','tenant_market','document','Evidence','test',now(),'evidence-item.v1.0.0','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`,
		`INSERT INTO sboms (id,tenant_id,evidence_id,format,spec_version,component_count,components) VALUES ('sbom_market','tenant_market','ev_market','cyclonedx','1.6',0,'[]')`,
		`INSERT INTO vulnerability_scans (id,tenant_id,evidence_id,scanner,target_ref,summary,findings) VALUES ('scan_market','tenant_market','ev_market','scanner','collector','{}','[]')`,
		`INSERT INTO signing_keys (id,tenant_id,kid,algorithm,status,public_key,valid_from) VALUES ('key_other','tenant_other','kid','Ed25519','active','public',now())`,
		`INSERT INTO signatures (id,tenant_id,subject_type,subject_id,key_id,algorithm,value) VALUES ('sig_other','tenant_other','collector','market_other','key_other','Ed25519','value')`,
		`INSERT INTO evidence_items (id,tenant_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status) VALUES ('ev_other','tenant_other','document','Evidence','test',now(),'evidence-item.v1.0.0','sha256:payload','sha256:canonical','canonical-json.v1','L2','pending')`,
		`INSERT INTO sboms (id,tenant_id,evidence_id,format,spec_version,component_count,components) VALUES ('sbom_other','tenant_other','ev_other','cyclonedx','1.6',0,'[]')`,
		`INSERT INTO vulnerability_scans (id,tenant_id,evidence_id,scanner,target_ref,summary,findings) VALUES ('scan_other','tenant_other','ev_other','scanner','collector','{}','[]')`,
	} {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			t.Fatalf("fixture %s: %v", statement, err)
		}
	}
	valid, err := store.GetMarketplaceCollectorPoint(ctx, "tenant_market", "market_b")
	if err != nil || !valid.SignatureFound || !valid.SBOMFound || !valid.ScanFound {
		t.Fatalf("valid point=%#v error=%v", valid, err)
	}
	foreignRefs, err := store.GetMarketplaceCollectorPoint(ctx, "tenant_market", "market_c")
	if err != nil || foreignRefs.SignatureFound || foreignRefs.SBOMFound || foreignRefs.ScanFound {
		t.Fatalf("foreign references point=%#v error=%v", foreignRefs, err)
	}
}

func TestPostgresMarketplaceCollectorQueryIndexMigrationRoundTrip(t *testing.T) {
	store := isolatedRelationalTestStore(t)
	check := func(want bool) {
		t.Helper()
		rows, err := store.pool.Query(t.Context(), `SELECT indexname,indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname IN ('marketplace_collectors_tenant_created_id_idx','marketplace_collectors_tenant_id_idx')`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		indexes := map[string]string{}
		for rows.Next() {
			var name, definition string
			if err := rows.Scan(&name, &definition); err != nil {
				t.Fatal(err)
			}
			indexes[name] = definition
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		for name, columns := range map[string]string{
			"marketplace_collectors_tenant_created_id_idx": "(tenant_id, created_at, id)",
			"marketplace_collectors_tenant_id_idx":         "(tenant_id, id)",
		} {
			if want && !strings.Contains(indexes[name], columns) {
				t.Fatalf("missing index %q: %q", name, indexes[name])
			}
			if !want && indexes[name] != "" {
				t.Fatalf("down migration retained index %q", name)
			}
		}
	}
	check(true)
	for _, migration := range []struct {
		file string
		want bool
	}{
		{file: "../../../migrations/20260929000400_marketplace_collector_list_indexes.down.sql"},
		{file: "../../../migrations/20260929000400_marketplace_collector_list_indexes.up.sql", want: true},
	} {
		statement, err := os.ReadFile(migration.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.pool.Exec(t.Context(), string(statement)); err != nil {
			t.Fatalf("run migration %q: %v", migration.file, err)
		}
		check(migration.want)
	}
}
