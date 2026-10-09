package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type signingKeyQueryFake struct {
	calls int
	err   error
}

func (f *signingKeyQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, _ appquery.PageRequest, _ *appquery.SortKey) (appquery.Result[verificationdomain.SigningKey], error) {
	f.calls++
	if f.err != nil {
		return appquery.Result[verificationdomain.SigningKey]{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	status, _ := verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusActive)
	return appquery.Result[verificationdomain.SigningKey]{Items: []verificationdomain.SigningKey{{ID: "sign_database", TenantID: actor.TenantID, KID: "kid_database", Version: 1, Provider: "local_ed25519", Algorithm: "Ed25519", Status: status, PublicKey: "public-value", ValidFrom: now, CreatedAt: now}}}, nil
}

func TestSigningKeyHandlerUsesFocusedQueryAndRejectsMalformedPagination(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	query := &signingKeyQueryFake{}
	server, err := newLegacyServerFixtureWithOptionsContext(t.Context(), ledger, ServerOptions{SigningKeyQuery: query})
	if err != nil {
		t.Fatal(err)
	}
	response := getRaw(t, server, secret, "/v1/signing-keys?page_size=1&sort=id&direction=desc", http.StatusOK)
	var page struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			PageSize int `json:"page_size"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Data) != 1 || page.Data[0].ID != "sign_database" || page.Meta.PageSize != 1 || query.calls != 1 || strings.Contains(response.Body.String(), "private") {
		t.Fatalf("signing key response=%s calls=%d error=%v", response.Body.String(), query.calls, err)
	}
	for _, path := range []string{"/v1/signing-keys?page_size=1&page_size=2", "/v1/signing-keys?sort=unknown", "/v1/signing-keys?cursor=forged", "/v1/signing-keys?limit=1"} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/signing-keys", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("invalid requests reached signing query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{application.ErrForbidden, http.StatusForbidden},
		{verificationquery.ErrSigningKeyValidation, http.StatusBadRequest},
		{verificationquery.ErrSigningKeyProjection, http.StatusConflict},
	} {
		query.err = test.err
		getRaw(t, server, secret, "/v1/signing-keys", test.status)
	}
}
