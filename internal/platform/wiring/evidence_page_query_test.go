package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func evidencePageNativeHTTP(t *testing.T, store *postgres.Store, path string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	o.PaginationSecret = []byte("stable-native-evidence-page-fixture")
	if o.EvidencePageQuery == nil {
		t.Fatal("native evidence pages missing")
	}
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", path, nil).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-excluded") || strings.Contains(w.Body.String(), "private-foreign") || want != 200 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native evidence page status=%d want=%d canary=%t: %s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	return w.Body.String()
}

func TestPostgresEvidencePagesNativeHTTPScopesCursorAndFilters(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceBundleNative(t, p)
	exec := func(q string) {
		t.Helper()
		if _, err := p.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE role_bindings SET resource_type='project',resource_id='project'WHERE id='grant';UPDATE evidence_items SET title='Visible',subtype='manual',source_system='source',collector_id='collector',tags='["tag"]',subject_refs='[{"type":"artifact","id":"artifact","digest":"digest"}]',metadata='{"precise":9007199254740993}',created_at='2026-10-06T00:00:00Z'WHERE id='selected';UPDATE evidence_items SET title='private-excluded',metadata=jsonb_build_object('data',repeat('private-excluded',100000))WHERE id='excluded';UPDATE evidence_items SET title='private-foreign'WHERE id='foreign-evidence'`)
	exec(`INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,type,subtype,title,source_system,collector_id,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,subject_refs,tags,metadata,created_at)SELECT 'selected-'||suffix,tenant_id,product_id,project_id,release_id,type,subtype,title,source_system,collector_id,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,subject_refs,tags,metadata,created_at FROM evidence_items CROSS JOIN (VALUES('b'),('c'))s(suffix)WHERE id='selected'`)
	paths := []string{"/v1/evidence?page_size=1&sort=id&direction=asc", "/v1/evidence/search?type=document&subtype=manual&source=source&collector_id=collector&verification_status=pending&subject_type=artifact&subject_id=digest&tag=tag&created_after=2026-10-06T00%3A00%3A00Z&created_before=2026-10-06T00%3A00%3A00Z&page_size=1&sort=id&direction=asc"}
	for _, first := range paths {
		path := first
		var ids []string
		for range 3 {
			body := evidencePageNativeHTTP(t, store, path, 200)
			if !strings.Contains(body, `9007199254740993`) {
				t.Fatal("page rounded public metadata", body)
			}
			var e struct {
				Data []domain.EvidenceItem `json:"data"`
				Meta struct {
					Next string `json:"next_cursor"`
				} `json:"meta"`
			}
			if err := json.Unmarshal([]byte(body), &e); err != nil || len(e.Data) != 1 {
				t.Fatal("page shape changed", body, err)
			}
			ids = append(ids, e.Data[0].ID)
			if e.Meta.Next == "" {
				break
			}
			path = first + "&cursor=" + e.Meta.Next
		}
		if strings.Join(ids, ",") != "selected,selected-b,selected-c" {
			t.Fatal("visibility/order before limit changed", ids)
		}
	}
	evidencePageNativeHTTP(t, store, "/v1/evidence/search?source=a&source_system=b", 400)
	evidencePageNativeHTTP(t, store, "/v1/evidence?release_id=a&release_id=b", 400)
	evidencePageNativeHTTP(t, store, "/v1/evidence/search?tag=bad%00tag", 400)
	evidencePageNativeHTTP(t, store, "/v1/evidence/search?created_after=0000-01-01T00%3A00%3A00Z", 400)
	exec(`UPDATE role_bindings SET resource_type='product',resource_id='other-product'WHERE id='grant'`)
	// A read of explicitly excluded product data must not trigger validation of
	// unrelated formerly authorized evidence or worker projections.
	exec(`UPDATE evidence_items SET type='parser_normalization'WHERE id='selected'`)
	q, err := BuildEvidencePageQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"evidence:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "other-product", Scopes: []string{"evidence:read"}}}}
	page, err := q.ListPage(t.Context(), a, evidencequery.EvidencePageFilter{}, appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, nil)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "excluded" {
		t.Fatal("unrelated worker projection affected authorized page", page, err)
	}
}

func TestPostgresEvidencePagesValidateInferredParentsAndWorkerProvenance(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceCreationNative(t, p)
	exec := func(q string) {
		t.Helper()
		if _, err := p.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO evidence_items(id,tenant_id,build_id,deployment_id,type,title,source_system,observed_at,evidence_version,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,created_at)VALUES('build-only','tenant','build',NULL,'document','Visible','test',now(),1,'evidence-item.v1.0.0','hash','hash','json','L2','pending',now()),('deployment-only','tenant',NULL,'rollback','document','Visible','test',now(),1,'evidence-item.v1.0.0','hash','hash','json','L2','pending',now())`)
	q, err := BuildEvidencePageQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	request := appquery.PageRequest{PageSize: 10, Sort: appquery.SortID, Direction: appquery.Ascending}
	a := domain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"evidence:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "project", ResourceID: "project", Scopes: []string{"evidence:read"}}}}
	page, err := q.ListPage(t.Context(), a, evidencequery.EvidencePageFilter{}, request, nil)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "build-only" {
		t.Fatal("project inference failed", page, err)
	}
	a.ResourceGrants[0] = domain.ResourceGrant{ResourceType: "release", ResourceID: "release", Scopes: []string{"evidence:read"}}
	page, err = q.ListPage(t.Context(), a, evidencequery.EvidencePageFilter{}, request, nil)
	if err != nil || len(page.Items) != 2 {
		t.Fatal("release inference failed", page, err)
	}
	exec(`UPDATE evidence_items SET type='parser_normalization'WHERE id='build-only'`)
	if _, err := q.ListPage(t.Context(), a, evidencequery.EvidencePageFilter{}, request, nil); !errors.Is(err, evidencequery.ErrConflict) {
		t.Fatal("unvalidated worker evidence was disclosed", err)
	}
	exec(`UPDATE evidence_items SET type='document'WHERE id='build-only';UPDATE build_runs SET project_id='other-project'WHERE id='build'`)
	if _, err := q.ListPage(t.Context(), a, evidencequery.EvidencePageFilter{}, request, nil); err == nil {
		t.Fatal("inconsistent selected parents were silently filtered")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := q.ListPage(ctx, a, evidencequery.EvidencePageFilter{}, request, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("lost page cancellation", err)
	}
	var audits, keys int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records)`).Scan(&audits, &keys); err != nil || audits != 0 || keys != 0 {
		t.Fatal("query wrote side effects", audits, keys, err)
	}
}

func TestBuildEvidencePageQueryRequiresReader(t *testing.T) {
	if _, err := BuildEvidencePageQuery(nil); err == nil {
		t.Fatal("missing reader accepted")
	}
}

func TestPostgresEvidencePagesRefillAfterCanonicalGrantDenial(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedEvidenceBundleNative(t, p)
	if _, err := p.Exec(t.Context(), `INSERT INTO evidence_items(id,tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status)SELECT 'selected-next',tenant_id,product_id,project_id,release_id,type,title,source_system,observed_at,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status FROM evidence_items WHERE id='selected'`); err != nil {
		t.Fatal(err)
	}
	in := evidencequery.EvidencePageRequest{TenantID: "tenant", TenantWide: true, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	page, err := store.PageEvidence(t.Context(), in, func(refs application.ResourceReferences) error {
		if refs.ProductID != "product" {
			return application.ErrForbidden
		}
		return nil
	})
	if err != nil || len(page.Items) != 1 || page.Items[0].Item.ID != "selected" || page.Next == nil || page.Next.ID != "selected" {
		t.Fatal("denied candidate exhausted page/lookahead", page, err)
	}
}
