package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestControlNativeQueryFixtureUsesCurrentRepositoriesAndDiscardsFailedCommits(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	foreign := seedControlFixtureScope(t, ledger, "Foreign")
	factory := &operatorQueryFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("control read used aggregate clock") }})
	f := controlReadFixture{catalogFixtureCommands{ledger: rebound}}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"controls:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"controls:read"}}}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	frameworks, err := f.ListFrameworksPage(t.Context(), human, page, nil)
	if err != nil || !reflect.DeepEqual(frameworks.Items, []riskdomain.ControlFramework{riskdomain.ControlFramework(owner.framework)}) || frameworks.Next != nil {
		t.Fatal("framework page used aggregate cache or lost complete DTO", err)
	}
	v, err := f.GetSecurityControl(t.Context(), human, owner.control.ID)
	if err != nil || !reflect.DeepEqual(securityControlFromQuery(v), owner.control) {
		t.Fatal("control point used aggregate cache or lost definition", err)
	}
	v.EvidenceRequirements[0].Type, v.Applicability[0], v.Limitations[0] = "modified", "modified", "modified"
	again, err := f.GetSecurityControl(t.Context(), human, owner.control.ID)
	if err != nil || !reflect.DeepEqual(securityControlFromQuery(again), owner.control) {
		t.Fatal("definition alias changed current record", err)
	}
	if v, err := f.GetSecurityControl(t.Context(), human, foreign.control.ID); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, riskdomain.SecurityControl{}) {
		t.Fatal("foreign control disclosed", err)
	}
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"controls:read"}}}
	if _, err := f.GetSecurityControl(t.Context(), human, owner.control.ID); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("product grant conferred tenant inventory access", err)
	}
	human.ResourceGrants = nil
	if _, err := f.ListFrameworksPage(t.Context(), human, page, nil); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("revoked grant conferred inventory access", err)
	}
	factory.fail = true
	for _, point := range []bool{false, true} {
		rollbacks := factory.rollbacks
		if point {
			if v, err := f.GetSecurityControl(t.Context(), owner.actor, owner.control.ID); err == nil || !reflect.DeepEqual(v, riskdomain.SecurityControl{}) {
				t.Fatal("failed commit exposed definition", err)
			}
		} else if v, err := f.ListFrameworksPage(t.Context(), owner.actor, page, nil); err == nil || v.Items != nil || v.Next != nil {
			t.Fatal("failed commit exposed inventory", err)
		}
		if factory.rollbacks != rollbacks+1 {
			t.Fatal("failed read did not roll back")
		}
	}
	server, err := newLegacyServerFixtureWithOptions(rebound, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/control-frameworks", "/v1/controls/" + owner.control.ID} {
		body := getRaw(t, server, "fixture", path, 500).Body.String()
		if strings.Contains(body, "private-query") || strings.Contains(body, `"data"`) || strings.Contains(body, `"evidence_requirements"`) {
			t.Fatal("failed HTTP read leaked private error or partial DTO", body)
		}
	}
	factory.fail = false
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("control reads changed state", err)
	}
}

func TestControlNativeQueryFixtureRequiresRepositoriesAndKeepsExplicitPorts(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	f := controlReadFixture{catalogFixtureCommands{ledger: ledger}}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"controls:read"}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	if _, err := f.ListFrameworksPage(t.Context(), a, page, nil); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing repository restored framework cache", err)
	}
	if _, err := f.GetSecurityControl(t.Context(), a, "control"); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing repository restored control cache", err)
	}
	var nilContext context.Context
	if _, err := f.GetSecurityControl(nilContext, a, "control"); !errors.Is(err, app.ErrValidation) {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.ListFrameworksPage(ctx, a, page, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	explicit := &controlsQueryFake{}
	s := &Server{controlsQuery: explicit}
	s.bindControlFixtureQueries(ledger)
	if s.controlsQuery != explicit {
		t.Fatal("rebind replaced explicit query port")
	}
}
