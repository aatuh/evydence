package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestControlTemplateFixtureUsesFocusedStaticCatalogWithoutAggregate(t *testing.T) {
	f := controlReadFixture{}
	actor := domain.Actor{TenantID: "tenant", UserID: "reader", Scopes: []string{app.ScopeControlsRead}}
	before := riskdomain.BuiltinTemplatePacks()
	got, err := f.ListTemplatePacks(t.Context(), actor)
	if err != nil || !reflect.DeepEqual(got, before) || len(got) == 0 || len(got[0].Controls) == 0 {
		t.Fatal("static catalog lost owned definitions", err)
	}
	got[0].Controls[0].Title = "changed"
	again, err := f.ListTemplatePacks(t.Context(), actor)
	if err != nil || !reflect.DeepEqual(again, before) {
		t.Fatal("static catalog aliases returned definitions", err)
	}
	for _, denied := range []domain.Actor{
		{TenantID: "tenant", Scopes: []string{app.ScopeControlsRead}},
		{UserID: "reader", Scopes: []string{app.ScopeControlsRead}},
	} {
		if value, err := f.ListTemplatePacks(t.Context(), denied); !errors.Is(err, app.ErrUnauthorized) || value != nil {
			t.Fatal("anonymous static catalog disclosure", err)
		}
	}
	actor.Scopes = nil
	if value, err := f.ListTemplatePacks(t.Context(), actor); !errors.Is(err, app.ErrForbidden) || value != nil {
		t.Fatal("scope removal left catalog accessible", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := f.ListTemplatePacks(ctx, actor); !errors.Is(err, context.Canceled) || value != nil {
		t.Fatal("cancelled catalog returned data", err)
	}
}
