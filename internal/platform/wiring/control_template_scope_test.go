package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestPostgresControlTemplateTenantScopeDoesNotReadInstalledMetadata(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	if _, err := p.Exec(t.Context(), `INSERT INTO tenants(id,name)VALUES('tenant','Templates');INSERT INTO control_frameworks(id,tenant_id,name,slug,version,description,status,schema_version,created_at)VALUES('existing','tenant',repeat('private-',1200000),'evydence-cra-readiness','1',repeat('private-',1200000),'active','control-framework.v1.0.0',now())`); err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
		locker, ok := repos.Controls.(interface {
			LockControlTemplateTenant(context.Context, string) error
		})
		if !ok {
			t.Fatal("missing flat template tenant guard")
		}
		return locker.LockControlTemplateTenant(ctx, "tenant")
	}); err != nil {
		t.Fatal(err)
	}
	var audits, replays int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM idempotency_records)`).Scan(&audits, &replays); err != nil || audits != 0 || replays != 0 {
		t.Fatal("read-only tenant guard wrote effects", audits, replays, err)
	}
}

func TestPostgresControlTemplateGuardRejectsMissingAndMalformedTenant(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	commands, err := BuildControlTemplateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenant string
		want   error
	}{
		{"missing", riskapp.ErrNotFound}, {" tenant", riskapp.ErrValidation}, {"bad\x00tenant", riskapp.ErrValidation}, {string([]byte{0xff}), riskapp.ErrValidation}, {strings.Repeat("x", 1025), riskapp.ErrValidation},
	} {
		a := identitydomain.Actor{TenantID: tc.tenant, KeyID: "caller", Scopes: []string{"controls:admin"}}
		if err := commands.AuthorizeControlTemplateInstallation(t.Context(), a, "evydence-cra-readiness"); !errors.Is(err, tc.want) {
			t.Fatal("invalid tenant scope accepted", err)
		}
	}
	if got := controlTemplateNativeCounts(t, p); got != [6]int{} {
		t.Fatal("invalid scope wrote effects", got)
	}
}
