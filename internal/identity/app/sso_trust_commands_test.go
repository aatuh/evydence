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

type ssoProviderTestHasher struct{ fail bool }

func (h ssoProviderTestHasher) Hash(v any) (string, error) {
	if h.fail {
		return "", errors.New("private trust hash")
	}
	return application.NormalizedJSONHash(v)
}
func ssoTrustForTest(t *testing.T) (*SSOProviderCommands, *ssoProviderFixture, identitydomain.Actor, UpdateSSOProviderTrustMaterialInput) {
	t.Helper()
	f := &ssoProviderFixture{}
	s, a, in := ssoProviderForTest(t, f)
	p, err := s.CreateSSOProvider(t.Context(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	f.current = &p
	f.providers = nil
	f.audits = nil
	f.calls = 0
	jwks := map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "rotated", "crv": "Ed25519", "x": "new-public-only"}}}
	return s, f, a, UpdateSSOProviderTrustMaterialInput{JWKS: jwks}
}
func TestSSOTrustCommandsRotateOwnedProviderWithCanonicalAudit(t *testing.T) {
	s, f, a, in := ssoTrustForTest(t)
	before := cloneSSOProvider(*f.current)
	if err := s.AuthorizeUpdateSSOProviderTrustMaterial(t.Context(), a, " sso_new ", in); err != nil || !reflect.DeepEqual(before, *f.current) || len(f.audits) != 0 {
		t.Fatal("trust replay guard emitted effects", err)
	}
	out, err := s.UpdateSSOProviderTrustMaterial(t.Context(), a, "sso_new", in)
	if err != nil || out.ID != before.ID || out.CreatedAt != before.CreatedAt || out.Issuer != before.Issuer || out.Name != before.Name || out.TrustMaterialUpdatedAt == nil || out.TrustMaterialUpdatedAt.Location() != time.UTC || out.TrustMaterialUpdatedAt.Nanosecond()%1000 != 0 || len(f.audits) != 1 {
		t.Fatal("rotation changed immutable metadata", err)
	}
	if audit := f.audits[0]; audit.EntryType != "sso_provider.trust_material_updated" || audit.SubjectID != out.ID || audit.ActorID != a.UserID || !strings.HasPrefix(audit.PayloadHash, "sha256:") {
		t.Fatal("trust audit attribution/hash lost")
	}
	want, err := (ssoProviderTestHasher{}).Hash(struct {
		ProviderID   string         `json:"provider_id"`
		JWKS         map[string]any `json:"jwks,omitempty"`
		Certificates []string       `json:"saml_signing_certificates,omitempty"`
		UpdatedAt    string         `json:"updated_at"`
	}{out.ID, out.JWKS, out.SAMLSigningCertificates, out.TrustMaterialUpdatedAt.Format(time.RFC3339Nano)})
	if err != nil || want != f.audits[0].PayloadHash {
		t.Fatal("canonical trust hash contract changed", err)
	}
	in.JWKS["keys"].([]any)[0].(map[string]any)["x"] = "mutated-input"
	out.JWKS["keys"].([]any)[0].(map[string]any)["kid"] = "mutated-output"
	if key := f.current.JWKS["keys"].([]any)[0].(map[string]any); key["x"] != "new-public-only" || key["kid"] != "rotated" {
		t.Fatal("trust rotation aliases caller")
	}
}
func TestSSOTrustCommandsRejectInvalidMaterialIDsAndForeignProviders(t *testing.T) {
	for _, change := range []func(*UpdateSSOProviderTrustMaterialInput){func(in *UpdateSSOProviderTrustMaterialInput) { in.JWKS["keys"].([]any)[0].(map[string]any)["d"] = nil }, func(in *UpdateSSOProviderTrustMaterialInput) {
		in.JWKS["keys"].([]any)[0].(map[string]any)["kid"] = "bad\x00"
	}, func(in *UpdateSSOProviderTrustMaterialInput) { in.SAMLSigningCertificates = []string{"bad"} }} {
		s, f, a, in := ssoTrustForTest(t)
		change(&in)
		if err := s.AuthorizeUpdateSSOProviderTrustMaterial(t.Context(), a, "sso_new", in); !errors.Is(err, ErrValidation) || f.calls != 0 {
			t.Fatal("invalid trust passed reservation guard", err)
		}
	}
	for _, id := range []string{"", "bad\x00", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		s, f, a, in := ssoTrustForTest(t)
		if err := s.AuthorizeUpdateSSOProviderTrustMaterial(t.Context(), a, id, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
			t.Fatal("invalid trust provider ID reached storage", err)
		}
	}
	for _, foreign := range []string{"tenant", "id", "absent"} {
		s, f, a, in := ssoTrustForTest(t)
		if foreign == "tenant" {
			f.current.TenantID = "other"
		}
		if foreign == "id" {
			f.current.ID = "other"
		}
		if foreign == "absent" {
			f.current = nil
		}
		if out, err := s.UpdateSSOProviderTrustMaterial(t.Context(), a, "sso_new", in); !errors.Is(err, ErrNotFound) || out.ID != "" || len(f.audits) != 0 {
			t.Fatal("foreign provider trust mutated", foreign, err)
		}
	}
	for _, kind := range []string{"oidc", "saml", "unknown"} {
		s, f, a, _ := ssoTrustForTest(t)
		f.current.Type = kind
		if err := s.AuthorizeUpdateSSOProviderTrustMaterial(t.Context(), a, "sso_new", UpdateSSOProviderTrustMaterialInput{}); !errors.Is(err, ErrValidation) || len(f.audits) != 0 {
			t.Fatal("empty or unsupported trust rotation accepted", kind, err)
		}
	}
}
func TestSSOTrustCommandsPublishNothingOnFailuresOrScopedAuthority(t *testing.T) {
	for _, phase := range []string{"auth", "lock", "read", "cas", "write", "audit", "commit", "cancel", "hash", "clock", "audit-id"} {
		s, f, a, in := ssoTrustForTest(t)
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
		out, err := s.UpdateSSOProviderTrustMaterial(ctx, a, "sso_new", in)
		cancel()
		if err == nil || out.ID != "" || !reflect.DeepEqual(before, *f.current) || len(f.audits) != 0 {
			t.Fatal("failed trust rotation published effects", phase, err)
		}
	}
	s, f, a, in := ssoTrustForTest(t)
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}
	if err := s.AuthorizeUpdateSSOProviderTrustMaterial(t.Context(), a, "sso_new", in); !errors.Is(err, application.ErrForbidden) || f.calls != 0 {
		t.Fatal("scoped human rotated provider", err)
	}
}

func TestSSOTrustCommandsApplySAMLPolicyWithoutMutatingUnrelatedMetadata(t *testing.T) {
	s, f, a, _ := ssoTrustForTest(t)
	f.current.Type = "saml"
	f.current.JWKS = nil
	f.current.SAMLSigningCertificates = []string{"old-public-certificate"}
	before := cloneSSOProvider(*f.current)
	// Certificate parsing is tested at the real policy boundary. This fake
	// isolates the command's provider-type rule and ownership of the result.
	s.config.TrustMaterial = &fakeTrustMaterial{certificates: []string{"normalized-public-certificate"}}
	in := UpdateSSOProviderTrustMaterialInput{SAMLSigningCertificates: []string{"raw-public-certificate"}}
	if err := s.AuthorizeUpdateSSOProviderTrustMaterial(t.Context(), a, before.ID, in); err != nil || !reflect.DeepEqual(before, *f.current) || len(f.audits) != 0 {
		t.Fatal("SAML guard mutated trust material", err)
	}
	out, err := s.UpdateSSOProviderTrustMaterial(t.Context(), a, before.ID, in)
	if err != nil || out.Type != "saml" || out.ID != before.ID || out.CreatedAt != before.CreatedAt || out.JWKS != nil || !reflect.DeepEqual(out.SAMLSigningCertificates, []string{"normalized-public-certificate"}) || out.TrustMaterialUpdatedAt == nil || len(f.audits) != 1 {
		t.Fatal("SAML rotation lost normalized public material", err)
	}
	want, err := (ssoProviderTestHasher{}).Hash(ssoTrustHashInput(out, *out.TrustMaterialUpdatedAt))
	if err != nil || f.audits[0].PayloadHash != want {
		t.Fatal("SAML rotation audit hashed different material", err)
	}
	out.SAMLSigningCertificates[0] = "mutated-output"
	in.SAMLSigningCertificates[0] = "mutated-input"
	if f.current.SAMLSigningCertificates[0] != "normalized-public-certificate" {
		t.Fatal("SAML rotation aliases caller")
	}
	if err := s.AuthorizeUpdateSSOProviderTrustMaterial(t.Context(), a, before.ID, UpdateSSOProviderTrustMaterialInput{JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "fixture", "crv": "Ed25519", "x": "public-only"}}}}); !errors.Is(err, ErrValidation) || len(f.audits) != 1 {
		t.Fatal("SAML provider accepted OIDC trust", err)
	}
}
