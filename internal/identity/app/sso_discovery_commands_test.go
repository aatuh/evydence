package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type ssoDiscoveryCommandFake struct {
	requests []OIDCDiscoveryRequest
	result   OIDCDiscoveryResult
	err      error
}

func (f *ssoDiscoveryCommandFake) FetchOIDCTrustMaterial(_ context.Context, r OIDCDiscoveryRequest) (OIDCDiscoveryResult, error) {
	f.requests = append(f.requests, r)
	return f.result, f.err
}

func ssoDiscoveryForTest(t *testing.T) (*SSOProviderCommands, *ssoProviderFixture, identitydomain.Actor, *ssoDiscoveryCommandFake) {
	t.Helper()
	s, f, a, in := ssoTrustForTest(t)
	d := &ssoDiscoveryCommandFake{result: OIDCDiscoveryResult{Issuer: f.current.Issuer, JWKS: in.JWKS}}
	s.config.OIDCDiscovery = d
	return s, f, a, d
}

func TestSSODiscoveryCommandsGuardWithoutNetworkAndCommitCanonicalAudit(t *testing.T) {
	s, f, a, d := ssoDiscoveryForTest(t)
	before := cloneSSOProvider(*f.current)
	if err := s.AuthorizeRefreshSSOProviderOIDCTrustMaterial(t.Context(), a, " sso_new "); err != nil || len(d.requests) != 0 || !reflect.DeepEqual(before, *f.current) || len(f.audits) != 0 {
		t.Fatal("discovery guard fetched or mutated", err)
	}
	d.result.Issuer = " " + strings.TrimRight(before.Issuer, "/") + "/// "
	out, err := s.RefreshSSOProviderOIDCTrustMaterial(t.Context(), a, before.ID)
	if err != nil || len(d.requests) != 1 || d.requests[0] != (OIDCDiscoveryRequest{TenantID: a.TenantID, ProviderID: before.ID, Issuer: before.Issuer}) || out.ID != before.ID || out.CreatedAt != before.CreatedAt || out.Issuer != before.Issuer || out.ClientID != before.ClientID || out.TrustMaterialUpdatedAt == nil || out.TrustMaterialUpdatedAt.Location() != time.UTC || out.TrustMaterialUpdatedAt.Nanosecond()%1000 != 0 || len(f.audits) != 1 {
		t.Fatal("discovery changed immutable provider metadata", err)
	}
	want, err := application.NormalizedJSONHash(struct {
		ProviderID string         `json:"provider_id"`
		Issuer     string         `json:"issuer"`
		JWKS       map[string]any `json:"jwks"`
		UpdatedAt  string         `json:"updated_at"`
	}{out.ID, out.Issuer, out.JWKS, out.TrustMaterialUpdatedAt.Format(time.RFC3339Nano)})
	if audit := f.audits[0]; err != nil || audit.EntryType != "sso_provider.oidc_trust_material_refreshed" || audit.SubjectID != out.ID || audit.ActorID != a.UserID || audit.PayloadHash != want {
		t.Fatal("discovery audit attribution or hash contract changed", err)
	}
	d.result.JWKS["keys"].([]any)[0].(map[string]any)["x"] = "mutated-provider"
	out.JWKS["keys"].([]any)[0].(map[string]any)["kid"] = "mutated-output"
	if key := f.current.JWKS["keys"].([]any)[0].(map[string]any); key["x"] != "new-public-only" || key["kid"] != "rotated" {
		t.Fatal("discovery retained provider/caller aliases")
	}
}

func TestSSODiscoveryCommandsRejectUntrustedProviderResultsWithoutEffects(t *testing.T) {
	for _, change := range []func(*ssoDiscoveryCommandFake){
		func(d *ssoDiscoveryCommandFake) { d.err = errors.New("private provider response") },
		func(d *ssoDiscoveryCommandFake) { d.result.Issuer = "https://other.example.test" },
		func(d *ssoDiscoveryCommandFake) { d.result.JWKS = nil },
		func(d *ssoDiscoveryCommandFake) {
			d.result.JWKS["keys"].([]any)[0].(map[string]any)["d"] = "private key"
		},
		func(d *ssoDiscoveryCommandFake) { d.result.JWKS["keys"].([]any)[0].(map[string]any)["kid"] = "bad\x00" },
		func(d *ssoDiscoveryCommandFake) {
			d.result.JWKS["keys"].([]any)[0].(map[string]any)["kid"] = string([]byte{0xff})
		},
		func(d *ssoDiscoveryCommandFake) {
			d.result.JWKS["keys"].([]any)[0].(map[string]any)["x"] = strings.Repeat("x", 65536)
		},
	} {
		s, f, a, d := ssoDiscoveryForTest(t)
		before := cloneSSOProvider(*f.current)
		change(d)
		out, err := s.RefreshSSOProviderOIDCTrustMaterial(t.Context(), a, before.ID)
		if !errors.Is(err, ErrVerificationFailed) || out.ID != "" || !reflect.DeepEqual(before, *f.current) || len(f.audits) != 0 {
			t.Fatal("untrusted discovery result replaced current trust", err)
		}
	}
}

func TestSSODiscoveryCommandsGuardAuthorityOwnershipTypeAndConfiguration(t *testing.T) {
	for _, phase := range []string{"scoped", "foreign", "absent", "saml", "disabled", "bad-id"} {
		s, f, a, d := ssoDiscoveryForTest(t)
		id, want := "sso_new", error(ErrValidation)
		switch phase {
		case "scoped":
			a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}
			want = application.ErrForbidden
		case "foreign":
			f.current.TenantID = "other"
			want = ErrNotFound
		case "absent":
			f.current = nil
			want = ErrNotFound
		case "saml":
			f.current.Type = "saml"
		case "disabled":
			s.config.OIDCDiscovery = nil
		case "bad-id":
			id = "bad\x00"
		}
		if err := s.AuthorizeRefreshSSOProviderOIDCTrustMaterial(t.Context(), a, id); !errors.Is(err, want) || len(d.requests) != 0 || len(f.audits) != 0 {
			t.Fatal("discovery guard bypassed boundary", phase, err)
		}
	}
}

func TestSSODiscoveryCommandsReturnNothingWhenTransactionOrHashFails(t *testing.T) {
	for _, phase := range []string{"auth", "lock", "read", "cas", "write", "audit", "commit", "cancel", "hash", "clock", "audit-id"} {
		s, f, a, _ := ssoDiscoveryForTest(t)
		before := cloneSSOProvider(*f.current)
		f.phase = phase
		ctx, cancel := context.WithCancel(t.Context())
		switch phase {
		case "cancel":
			f.cancel = cancel
		case "hash":
			s.config.Hasher = ssoProviderTestHasher{fail: true}
		case "clock":
			s.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
		case "audit-id":
			s.config.IDs = application.IDGeneratorFunc(func(string) string { return "" })
		}
		out, err := s.RefreshSSOProviderOIDCTrustMaterial(ctx, a, "sso_new")
		cancel()
		if err == nil || out.ID != "" || !reflect.DeepEqual(before, *f.current) || len(f.audits) != 0 {
			t.Fatal("failed discovery published effects", phase, err)
		}
	}
}
