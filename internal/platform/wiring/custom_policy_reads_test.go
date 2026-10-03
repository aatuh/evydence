package wiring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestPostgresCustomPolicyReaderBoundsAndCurrentEvidenceParents(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO custom_policies(id,tenant_id,name,version,rules,schema_version,created_at) VALUES('policy','tenant','Policy','1','[{"name":"r","severity":"low"}]','custom-policy.v1.0.0',now())`); err != nil {
		t.Fatal(err)
	}
	read := func(fn func(riskapp.CustomPolicyReader) error) error {
		return app.ExecuteUnitOfWork(ctx, store, func(_ context.Context, repos app.Repositories) error {
			return fn(repos.Risk.(riskapp.CustomPolicyReader))
		})
	}
	if err := read(func(r riskapp.CustomPolicyReader) error {
		p, err := r.ReadCustomPolicy(ctx, "tenant", "policy")
		if err != nil || p.Name != "Policy" || len(p.Rules) != 1 {
			t.Fatal(p, err)
		}
		_, err = r.ReadCustomPolicy(ctx, "other", "policy")
		if !errors.Is(err, app.ErrNotFound) {
			t.Fatal("foreign definition", err)
		}
		v, err := r.ReadCustomPolicyEvidencePresence(ctx, "tenant", "release", []string{"sbom", "threat_model"})
		if err != nil || !v["sbom"] || v["threat_model"] || len(v) != 2 {
			t.Fatal("presence facts", v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`'null'::jsonb`, `'{}'::jsonb`, `'[{"name":"r","severity":"low","evidence_type":null}]'::jsonb`, `'[{"name":"r","severity":"low","required":null}]'::jsonb`, `jsonb_build_array(jsonb_build_object('name',repeat('x',9000000),'severity','low'))`, `(SELECT jsonb_agg(jsonb_build_object('name','r','severity','low')) FROM generate_series(1,4097))`} {
		if _, err := pool.Exec(ctx, `UPDATE custom_policies SET rules=`+bad+` WHERE id='policy'`); err != nil {
			t.Fatal(err)
		}
		err := read(func(r riskapp.CustomPolicyReader) error {
			if _, err := r.ReadCustomPolicySubject(ctx, "tenant", "policy", "policy"); err != nil {
				t.Fatal("metadata loaded definition", err)
			}
			_, err := r.ReadCustomPolicy(ctx, "tenant", "policy")
			return err
		})
		if !errors.Is(err, app.ErrValidation) {
			t.Fatal("unbounded or malformed definition", err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE evidence_items SET product_id='other-product' WHERE id='ev-sbom'`); err != nil {
		t.Fatal(err)
	}
	if err := read(func(r riskapp.CustomPolicyReader) error {
		v, err := r.ReadCustomPolicyEvidencePresence(ctx, "tenant", "release", []string{"sbom"})
		if err != nil || v["sbom"] {
			t.Fatal("foreign evidence parent counted", v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := read(func(r riskapp.CustomPolicyReader) error {
		_, err := r.ReadCustomPolicyEvidencePresence(ctx, "tenant", "release", []string{"bad"})
		return err
	}); !errors.Is(err, app.ErrValidation) {
		t.Fatal("invalid evidence type", err)
	}
}
