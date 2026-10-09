package repositories_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestReportTemplateRepositoryReadsOneBoundedTenantOwnedDefinition(t *testing.T) {
	ctx, pool := openRepositoryTestPool(t)
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	repos := postgresrepositories.New(tx)
	for _, id := range []string{"ten_template", "ten_other"} {
		if err := repos.Identity.InsertTenant(ctx, domain.Tenant{ID: id, Name: id, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := repos.Packages.InsertCustomReportTemplate(ctx, domain.CustomReportTemplate{ID: "tpl_1", TenantID: "ten_template", Name: "Report", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id", "secret"}, Template: "{{never execute}}", SchemaVersion: "report-template.v1.0.0", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	value, err := repos.Packages.GetCustomReportTemplate(ctx, "ten_template", "tpl_1")
	if err != nil || value.ID != "tpl_1" || value.Name != "Report" || len(value.AllowedFields) != 2 || value.Template != "{{never execute}}" {
		t.Fatalf("template=%#v err=%v", value, err)
	}
	if value, err := repos.Packages.GetCustomReportTemplate(ctx, "ten_other", "tpl_1"); !errors.Is(err, app.ErrNotFound) || value.ID != "" {
		t.Fatalf("foreign=%#v err=%v", value, err)
	}
	// Name/version are already constrained by the tenant/name/version index's
	// row-size limit. Exercise storable oversized text and total-byte bounds.
	for _, column := range []string{"template", "report_type", "schema_version"} {
		if _, err := tx.Exec(ctx, `UPDATE report_templates SET `+column+`=$1 WHERE id='tpl_1'`, strings.Repeat("x", packageapp.MaxStoredReportTemplateBytes+1)); err != nil {
			t.Fatal(err)
		}
		if value, err := repos.Packages.GetCustomReportTemplate(ctx, "ten_template", "tpl_1"); !errors.Is(err, app.ErrConflict) || value.ID != "" {
			t.Fatalf("oversized %s returned template id=%s err=%v", column, value.ID, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE report_templates SET `+column+`='restored' WHERE id='tpl_1'`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE report_templates SET allowed_fields=ARRAY[repeat('x',$1::integer)] WHERE id='tpl_1'`, packageapp.MaxStoredReportTemplateBytes+1); err != nil {
		t.Fatal(err)
	}
	if value, err := repos.Packages.GetCustomReportTemplate(ctx, "ten_template", "tpl_1"); !errors.Is(err, app.ErrConflict) || value.ID != "" {
		t.Fatalf("oversized fields returned %s err=%v", value.ID, err)
	}
	if _, err := tx.Exec(ctx, `UPDATE report_templates SET allowed_fields=ARRAY['subject_id'],template=repeat('x',$1::integer),report_type=repeat('y',$1::integer) WHERE id='tpl_1'`, packageapp.MaxStoredReportTemplateBytes/2+1); err != nil {
		t.Fatal(err)
	}
	if value, err := repos.Packages.GetCustomReportTemplate(ctx, "ten_template", "tpl_1"); !errors.Is(err, app.ErrConflict) || value.ID != "" {
		t.Fatalf("oversized combined template returned %s err=%v", value.ID, err)
	}
	if _, err := tx.Exec(ctx, `UPDATE report_templates SET template='inert',report_type='metadata',allowed_fields=ARRAY[NULL::text] WHERE id='tpl_1'`); err != nil {
		t.Fatal(err)
	}
	if value, err := repos.Packages.GetCustomReportTemplate(ctx, "ten_template", "tpl_1"); !errors.Is(err, app.ErrConflict) || value.ID != "" {
		t.Fatalf("malformed fields returned %s err=%v", value.ID, err)
	}
}
