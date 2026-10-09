package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type custodyReaderStub struct {
	snapshot verificationapp.SigningCustodySnapshot
	err      error
	calls    int
	tenant   string
}

func (r *custodyReaderStub) ReadSigningCustodySnapshot(_ context.Context, tenant string) (verificationapp.SigningCustodySnapshot, error) {
	r.calls++
	r.tenant = tenant
	return r.snapshot, r.err
}

func TestSigningCustodyQueryAuthorizesBeforeReadingAndPreservesReadOnlyPolicy(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	expires := now.Add(-time.Hour)
	reader := &custodyReaderStub{snapshot: verificationapp.SigningCustodySnapshot{TenantID: "tenant", SigningProviders: []verificationdomain.SigningProvider{{ID: "provider", TenantID: "tenant", Type: "native_pkcs11_hsm"}}, ObjectRetentionPolicies: []verificationdomain.ObjectRetentionPolicy{{ID: "policy", TenantID: "tenant", Status: "verified", VerificationHash: "hash", VerificationExpiresAt: &expires}}}}
	service, err := NewSigningCustody(reader, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{
		{TenantID: "tenant", KeyID: "key"},
		{TenantID: "tenant", UserID: "user", Scopes: []string{"keys:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"keys:admin"}}}},
		{TenantID: "tenant", UserID: "user", Scopes: []string{"keys:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"keys:admin"}}}},
	} {
		if _, err := service.Report(t.Context(), actor); !errors.Is(err, application.ErrForbidden) || reader.calls != 0 {
			t.Fatalf("unauthorized reader calls=%d err=%v", reader.calls, err)
		}
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"keys:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"keys:admin"}}}}
	report, err := service.Report(t.Context(), actor)
	if err != nil || reader.tenant != "tenant" || report.TenantID != "tenant" || !report.GeneratedAt.Equal(now) || report.Checks[0].Result != "passed" || report.Checks[1].Result != "passed" || report.Checks[2].Result != "failed" || report.ObjectRetentionPolicies[0].Status != "stale" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if reader.snapshot.ObjectRetentionPolicies[0].Status != "verified" || len(reader.snapshot.ObjectRetentionPolicies[0].VerificationChecks) != 0 {
		t.Fatal("report mutated stored policy")
	}
	actor.UserID = ""
	actor.KeyID = "key"
	actor.ResourceGrants = nil
	if _, err := service.Report(t.Context(), actor); err != nil {
		t.Fatal("issued key denied", err)
	}
	actor.KeyID = ""
	actor.CollectorID = "collector"
	if _, err := service.Report(t.Context(), actor); err != nil {
		t.Fatal("scoped collector denied", err)
	}
}

func TestSigningCustodyQueryRejectsInvalidSnapshotsAndCancellation(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"keys:admin"}}
	for _, snapshot := range []verificationapp.SigningCustodySnapshot{
		{TenantID: "foreign"},
		{TenantID: "tenant", SigningProviders: []verificationdomain.SigningProvider{{ID: "provider", TenantID: "foreign"}}},
		{TenantID: "tenant", ObjectRetentionPolicies: []verificationdomain.ObjectRetentionPolicy{{ID: "policy", TenantID: "foreign"}}},
		{TenantID: "tenant", SigningProviders: []verificationdomain.SigningProvider{{ID: "", TenantID: "tenant"}}},
		{TenantID: "tenant", ObjectRetentionPolicies: []verificationdomain.ObjectRetentionPolicy{{ID: " bad", TenantID: "tenant"}}},
		{TenantID: "tenant", SigningProviders: []verificationdomain.SigningProvider{{ID: "same", TenantID: "tenant"}, {ID: "same", TenantID: "tenant"}}},
		{TenantID: "tenant", ObjectRetentionPolicies: []verificationdomain.ObjectRetentionPolicy{{ID: "same", TenantID: "tenant"}, {ID: "same", TenantID: "tenant"}}},
		{TenantID: "tenant", SigningProviders: make([]verificationdomain.SigningProvider, MaxSigningCustodyRecords+1)},
	} {
		reader := &custodyReaderStub{snapshot: snapshot}
		service, _ := NewSigningCustody(reader, time.Now)
		if report, err := service.Report(t.Context(), actor); !errors.Is(err, ErrSigningCustodyProjection) || report.TenantID != "" {
			t.Fatalf("invalid snapshot accepted report=%#v err=%v", report, err)
		}
	}
	reader := &custodyReaderStub{}
	service, _ := NewSigningCustody(reader, time.Now)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.Report(ctx, actor); !errors.Is(err, context.Canceled) || reader.calls != 0 {
		t.Fatal("cancellation reached reader", err)
	}
	//nolint:staticcheck // SA1012: explicit adversarial coverage of nil-context rejection.
	if _, err := service.Report(nil, actor); !errors.Is(err, ErrSigningCustodyValidation) {
		t.Fatal("nil context", err)
	}
	if _, err := service.Report(t.Context(), identitydomain.Actor{TenantID: "tenant", Scopes: []string{"keys:admin"}}); !errors.Is(err, application.ErrUnauthorized) || reader.calls != 0 {
		t.Fatal("anonymous reader", err)
	}
	if _, err := NewSigningCustody(nil, time.Now); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := NewSigningCustody(reader, nil); err == nil {
		t.Fatal("nil clock accepted")
	}
	reader.err = errors.New("backend failure")
	if _, err := service.Report(t.Context(), actor); !errors.Is(err, reader.err) {
		t.Fatal("reader failure hidden", err)
	}
}
