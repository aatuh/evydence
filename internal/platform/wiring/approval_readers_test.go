package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func seedApprovalSubjects(t *testing.T, ctx context.Context, store *postgres.Store, pool *pgxpool.Pool) {
	t.Helper()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `
 INSERT INTO waivers(id,tenant_id,scope_type,scope_id,owner,risk,reason,expires_at,schema_version,created_at)VALUES('waiver','tenant','release','release','Owner','high',repeat('x',9000000),now()+interval '1 day','waiver.v1',now());
 UPDATE vulnerability_scans SET findings='[{"id":"finding","vulnerability":"CVE-TEST"}]';
 INSERT INTO redaction_profiles(id,tenant_id,name,schema_version,created_at)VALUES('profile','tenant','Profile','redaction.v1',now());
 INSERT INTO customer_security_packages(id,tenant_id,product_id,release_id,redaction_profile_id,title,state,manifest,manifest_hash,expires_at,schema_version,created_at)VALUES('package','tenant','product','release','profile','Review','generated',jsonb_build_object('notes',repeat('x',9000000)),'sha256:manifest',now()+interval '1 day','package.v1',now());
 INSERT INTO contract_diffs(id,tenant_id,base_contract_id,target_contract_id,product_id,release_id,result,document,schema_version,created_at)VALUES('diff','tenant','contract','contract','product','release','compatible',jsonb_build_object('notes',repeat('x',9000000)),'diff.v1',now());
 INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||'{"id":"ev-review","type":"security_review"}'::jsonb)).* FROM evidence_items e WHERE id='ev-sbom';
 INSERT INTO manual_security_documents(id,tenant_id,product_id,release_id,document_type,title,sensitivity,evidence_id,payload_hash,schema_version,created_at)VALUES('review','tenant','product','release','security_review','Review','internal','ev-review','sha256:review','manual.v1',now());
 INSERT INTO custom_policies(id,tenant_id,name,version,rules,schema_version,created_at)VALUES('policy','tenant','Policy','1','[]','policy.v1',now())`); err != nil {
		t.Fatal(err)
	}
}
func TestPostgresApprovalReadersResolveOnlyBoundedCurrentOwnership(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	seedApprovalSubjects(t, ctx, store, pool)
	for _, test := range []struct {
		name, typ, id, change string
		want                  error
		tenantWide            bool
	}{
		{"release", "release", "release", "", nil, false}, {"diff", "contract_diff", "diff", "", nil, false}, {"waiver", "waiver", "waiver", "", nil, false}, {"review", "security_review", "review", "", nil, false}, {"package", "customer_package", "package", "", nil, false},
		{"finding waiver", "waiver", "waiver", `UPDATE waivers SET scope_type='finding',scope_id='finding'`, nil, false},
		{"control waiver", "waiver", "waiver", `UPDATE waivers SET scope_type='control',scope_id='control'`, nil, true},
		{"policy waiver", "waiver", "waiver", `UPDATE waivers SET scope_type='policy',scope_id='policy'`, nil, true},
		{"unknown type", "artifact", "artifact", "", app.ErrValidation, false}, {"missing", "release", "missing", "", app.ErrNotFound, false},
		{"foreign release", "release", "release", `UPDATE releases SET tenant_id='other' WHERE id='release'`, app.ErrNotFound, false},
		{"foreign product", "release", "release", `UPDATE products SET tenant_id='other' WHERE id='product'`, app.ErrNotFound, false},
		{"oversized ownership", "release", "release", `INSERT INTO products(id,tenant_id,name,slug)VALUES(repeat('x',1025),'tenant','Long','long');UPDATE releases SET product_id=repeat('x',1025) WHERE id='release'`, app.ErrValidation, false},
		{"foreign diff parent", "contract_diff", "diff", `UPDATE openapi_contracts SET tenant_id='other' WHERE id='contract'`, app.ErrNotFound, false},
		{"wrong diff source", "contract_diff", "diff", `UPDATE evidence_items SET type='sbom' WHERE id='ev-contract'`, app.ErrNotFound, false},
		{"foreign diff release", "contract_diff", "diff", `UPDATE contract_diffs SET release_id='missing'`, app.ErrNotFound, false},
		{"foreign package profile", "customer_package", "package", `UPDATE redaction_profiles SET tenant_id='other' WHERE id='profile'`, app.ErrNotFound, false},
		{"foreign review source", "security_review", "review", `UPDATE evidence_items SET tenant_id='other' WHERE id='ev-review'`, app.ErrNotFound, false},
		{"wrong review type", "security_review", "review", `UPDATE manual_security_documents SET document_type='other'`, app.ErrNotFound, false},
		{"wrong review source", "security_review", "review", `UPDATE evidence_items SET type='sbom' WHERE id='ev-review'`, app.ErrNotFound, false},
		{"unknown waiver scope", "waiver", "waiver", `UPDATE waivers SET scope_type='waiver',scope_id='waiver'`, app.ErrNotFound, false},
		{"missing waiver scope", "waiver", "waiver", `UPDATE waivers SET scope_id='missing'`, app.ErrNotFound, false},
		{"oversized waiver scope", "waiver", "waiver", `UPDATE waivers SET scope_id=repeat('x',1025)`, app.ErrValidation, false},
		{"foreign control parent", "waiver", "waiver", `UPDATE waivers SET scope_type='control',scope_id='control';UPDATE control_frameworks SET tenant_id='other' WHERE id='fw'`, app.ErrNotFound, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
			if test.change != "" {
				if _, err := tx.Exec(ctx, test.change); err != nil {
					t.Fatal(err)
				}
			}
			repos := repositories.New(tx)
			r, ok := repos.Governance.(riskapp.ApprovalReader)
			if !ok {
				t.Fatal("governance lacks bounded approval reader")
			}
			v, err := r.ReadApprovalSubject(ctx, "tenant", test.typ, test.id)
			if !errors.Is(err, test.want) {
				t.Fatal("current parent contract changed", v, err, test.want)
			}
			if err == nil && (v.Type != test.typ || v.ID != test.id || v.TenantID != "tenant" || !test.tenantWide && (v.ProductID != "product" || v.ReleaseID != "release") || test.tenantWide && (v.ProductID != "" || v.ReleaseID != "")) {
				t.Fatal("approval ownership changed", v)
			}
			if _, err := r.ReadApprovalSubject(ctx, "other", test.typ, test.id); err == nil {
				t.Fatal("foreign subject exposed")
			}
		})
	}
	err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Governance.(riskapp.ApprovalReader)
		if !ok {
			t.Fatal("governance lacks bounded approval reader")
		}
		for _, test := range []struct {
			tenant, id string
			want       bool
		}{{"tenant", "ev-sbom", true}, {"other", "ev-sbom", false}, {"tenant", "missing", false}} {
			v, err := r.ApprovalEvidenceExists(ctx, test.tenant, test.id)
			if err != nil || v != test.want {
				t.Fatal("evidence existence changed", v, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApprovalReadersRejectMissingTransactionsAndContexts(t *testing.T) {
	r := repositories.New(nil).Governance.(riskapp.ApprovalReader)
	if _, err := r.ReadApprovalSubject(t.Context(), "tenant", "release", "release"); !errors.Is(err, app.ErrValidation) {
		t.Fatal(err)
	}
	if _, err := r.ApprovalEvidenceExists(t.Context(), "tenant", "evidence"); !errors.Is(err, app.ErrValidation) {
		t.Fatal(err)
	}
}
