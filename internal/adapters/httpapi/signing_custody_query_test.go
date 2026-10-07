package httpapi

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type custodyQueryFake struct {
	calls int
	err   error
}

func (f *custodyQueryFake) Report(_ context.Context, actor identitydomain.Actor) (verificationdomain.SigningCustodyReviewReport, error) {
	f.calls++
	if f.err != nil {
		return verificationdomain.SigningCustodyReviewReport{}, f.err
	}
	return verificationdomain.SigningCustodyReviewReport{ReportType: "signing_custody_review", TenantID: actor.TenantID, SigningProviders: []verificationdomain.SigningProvider{{ID: "durable_provider", TenantID: actor.TenantID, Type: "native_pkcs11_hsm", KeyRef: "pkcs11:object=signing"}}, ObjectRetentionPolicies: []verificationdomain.ObjectRetentionPolicy{{ID: "durable_policy", TenantID: actor.TenantID, Status: "stale"}}, Checks: []verificationdomain.VerifyCheck{{Name: "object_lock_proof_recorded", Result: "failed"}}, Limitations: []string{"Recorded metadata is not proof of custody."}, GeneratedAt: time.Now().UTC()}, nil
}

type custodyFixtureQuerySpy struct {
	custodyFixtureQuery
	calls int
}

func (f *custodyFixtureQuerySpy) Report(ctx context.Context, actor domain.Actor) (verificationdomain.SigningCustodyReviewReport, error) {
	f.calls++
	return f.custodyFixtureQuery.Report(ctx, actor)
}

func TestSigningCustodyHandlerUsesDurableQueryWithoutFallbackAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &custodyQueryFake{}
	server.signingCustodyQuery = query
	if _, exists := reflect.TypeFor[Server]().FieldByName("verification"); exists {
		t.Fatal("broad Verification fallback binding still exists")
	}
	response := getRaw(t, server, secret, "/v1/reports/custody-review", http.StatusOK)
	if query.calls != 1 || !strings.Contains(response.Body.String(), `"id":"durable_provider"`) || !strings.Contains(response.Body.String(), `"status":"stale"`) || strings.Contains(response.Body.String(), `"private`) {
		t.Fatalf("focused report %s calls=%d", response.Body.String(), query.calls)
	}
	getRawNoAuth(t, server, "/v1/reports/custody-review", http.StatusUnauthorized)
	getRaw(t, server, secret, "/v1/reports/custody-review?unknown=value", http.StatusBadRequest)
	if query.calls != 1 {
		t.Fatal("invalid or anonymous request reached query")
	}
	for _, tc := range []struct {
		err    error
		status int
	}{
		{application.ErrForbidden, http.StatusForbidden}, {application.ErrUnauthorized, http.StatusUnauthorized},
		{verificationquery.ErrSigningCustodyValidation, http.StatusBadRequest}, {verificationquery.ErrSigningCustodyProjection, http.StatusConflict},
		{errors.New("private-database-detail"), http.StatusInternalServerError},
	} {
		query.err = tc.err
		response := getRaw(t, server, secret, "/v1/reports/custody-review", tc.status)
		if strings.Contains(response.Body.String(), "private-database-detail") {
			t.Fatal("internal detail leaked")
		}
	}
	if query.calls != 6 {
		t.Fatal("query errors bypassed the focused port", query.calls)
	}
	// Local test data is now supplied through an explicit focused fixture
	// reader, not by removing the runtime port to select a broad fallback.
	fixture := &custodyFixtureQuerySpy{custodyFixtureQuery: custodyFixtureQuery{catalogFixtureCommands{ledger: server.ledger}}}
	server.signingCustodyQuery = fixture
	getRaw(t, server, secret, "/v1/reports/custody-review?unknown=value", http.StatusBadRequest)
	getRaw(t, server, secret, "/v1/reports/custody-review", http.StatusOK)
	if fixture.calls != 1 || query.calls != 6 {
		t.Fatal("explicit focused fixture query was bypassed")
	}
}
