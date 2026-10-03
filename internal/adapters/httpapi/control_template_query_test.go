package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

type controlTemplateQueryFake struct {
	calls int
	err   error
}

func (f *controlTemplateQueryFake) ListTemplatePacks(context.Context, identitydomain.Actor) ([]riskdomain.ControlFrameworkTemplatePack, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return []riskdomain.ControlFrameworkTemplatePack{{ID: "tpl_focused", Slug: "focused", Name: "Focused", Version: "1", SchemaVersion: "control-framework-template-pack.v1.0.0"}}, nil
}

func TestControlTemplateHandlerUsesFocusedCatalogAndRejectsBadInput(t *testing.T) {
	server, secret := testServer(t)
	query := &controlTemplateQueryFake{}
	server.controlTemplateQuery = query
	response := getRaw(t, server, secret, "/v1/control-framework-template-packs", http.StatusOK)
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Data) != 1 || body.Data[0].ID != "tpl_focused" || query.calls != 1 {
		t.Fatalf("focused control templates=%s calls=%d error=%v", response.Body.String(), query.calls, err)
	}
	for _, path := range []string{
		"/v1/control-framework-template-packs?page_size=0",
		"/v1/control-framework-template-packs?page_size=1&page_size=2",
		"/v1/control-framework-template-packs?sort=unknown",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/control-framework-template-packs", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("invalid or unauthenticated request reached catalog %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{riskquery.ErrValidation, http.StatusBadRequest},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-catalog-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		response := getRaw(t, server, secret, "/v1/control-framework-template-packs", test.status)
		if strings.Contains(response.Body.String(), "private-catalog-detail") {
			t.Fatalf("internal catalog detail leaked: %s", response.Body.String())
		}
	}
}
