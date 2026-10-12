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

type ssoProviderFixture struct {
	providers []identitydomain.SSOProvider
	audits    []application.AuditEvent
	phase     string
	calls     int
	cancel    context.CancelFunc
	current   *identitydomain.SSOProvider
}

func (f *ssoProviderFixture) ExecuteSSOProvider(ctx context.Context, fn func(context.Context, SSOProviderTransaction) error) error {
	f.calls++
	staged := &ssoProviderFixture{phase: f.phase, cancel: f.cancel}
	if f.current != nil {
		p := cloneSSOProvider(*f.current)
		staged.current = &p
	}
	if err := fn(ctx, staged); err != nil {
		return err
	}
	if f.phase == "commit" {
		return errors.New("private provider commit")
	}
	f.providers = append(f.providers, staged.providers...)
	f.audits = append(f.audits, staged.audits...)
	f.current = staged.current
	return nil
}
func (f *ssoProviderFixture) ReadOwnedSSOProvider(_ context.Context, tenant, id string) (identitydomain.SSOProvider, error) {
	if f.phase == "read" {
		return identitydomain.SSOProvider{}, errors.New("private provider read")
	}
	if f.current == nil {
		return identitydomain.SSOProvider{}, ErrNotFound
	}
	return cloneSSOProvider(*f.current), nil
}
func (f *ssoProviderFixture) CompareAndSwapSSOProviderTrustMaterial(_ context.Context, expected, v identitydomain.SSOProvider) error {
	if f.phase == "cas" {
		return ErrConflict
	}
	if f.phase == "write" {
		return errors.New("private provider update")
	}
	if f.current == nil || !reflect.DeepEqual(*f.current, expected) {
		return ErrConflict
	}
	p := cloneSSOProvider(v)
	f.current = &p
	return nil
}
func (f *ssoProviderFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.phase == "auth" {
		return application.ErrForbidden
	}
	return NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *ssoProviderFixture) LockSSOProviderCreation(context.Context, string) error {
	if f.phase == "lock" {
		return ErrNotFound
	}
	return nil
}
func (f *ssoProviderFixture) InsertSSOProvider(_ context.Context, v identitydomain.SSOProvider) error {
	if f.phase == "write" {
		return errors.New("private provider write")
	}
	f.providers = append(f.providers, v)
	return nil
}
func (f *ssoProviderFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errors.New("private provider audit")
	}
	f.audits = append(f.audits, v)
	if f.cancel != nil {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func ssoProviderForTest(t *testing.T, f *ssoProviderFixture) (*SSOProviderCommands, identitydomain.Actor, CreateSSOProviderInput) {
	t.Helper()
	s, err := NewSSOProviderCommands(SSOProviderCommandConfig{Transactions: f, Authorizer: NewMembershipWriteAuthorizer(), TrustMaterial: PublicTrustMaterialValidator{}, Hasher: ssoProviderTestHasher{}, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 1, 2, 3, 123456789, time.FixedZone("fixture", 3600)) }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "operator", Scopes: []string{ScopeIdentityAdmin}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{ScopeIdentityAdmin}}}}
	in := CreateSSOProviderInput{Name: " Fixture ", Type: " oidc ", Issuer: " https://issuer.example.test/tenant/ ", ClientID: " client ", GroupsClaim: " groups ", RoleMapping: map[string]string{"maintainers": "tenant_admin", "unknown": "future-role"}, JWKS: map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "fixture", "crv": "Ed25519", "x": "public-only", "key_ops": []any{"verify"}}}}}
	return s, a, in
}
func TestSSOProviderCommandsPreservePublicMetadataAndAtomicAudit(t *testing.T) {
	for _, kind := range []string{"oidc", "saml"} {
		f := &ssoProviderFixture{}
		s, a, in := ssoProviderForTest(t, f)
		in.Type = " " + kind + " "
		v, err := s.CreateSSOProvider(t.Context(), a, in)
		if err != nil || v.ID != "sso_new" || v.TenantID != a.TenantID || v.Type != kind || v.Name != "Fixture" || v.Issuer != "https://issuer.example.test/tenant/" || v.ClientID != "client" || v.GroupsClaim != "groups" || v.Status != "active" || v.SchemaVersion != identitydomain.SSOProviderSchemaVersion || v.CreatedAt.Location() != time.UTC || v.CreatedAt.Nanosecond()%1000 != 0 || len(f.providers) != 1 || len(f.audits) != 1 {
			t.Fatal("provider creation contract changed", kind, err)
		}
		if audit := f.audits[0]; audit.EntryType != "sso_provider.created" || audit.SubjectType != "sso_provider" || audit.SubjectID != v.ID || audit.ActorType != "human_user" || audit.ActorID != a.UserID || audit.OccurredAt != v.CreatedAt {
			t.Fatal("provider audit attribution lost")
		}
		if err := s.AuthorizeCreateSSOProvider(t.Context(), a, in); err != nil || len(f.providers)+len(f.audits) != 2 {
			t.Fatal("provider replay guard emitted effects", err)
		}
		if _, err := s.CreateSSOProvider(t.Context(), a, in); err != nil || len(f.providers) != 2 {
			t.Fatal("new-key repeated registration became a conflict", err)
		}
		in.RoleMapping["maintainers"] = "mutated-input"
		in.JWKS["keys"].([]any)[0].(map[string]any)["x"] = "mutated-input"
		v.RoleMapping["unknown"] = "mutated-output"
		v.JWKS["keys"].([]any)[0].(map[string]any)["key_ops"].([]any)[0] = "mutated-output"
		stored := f.providers[0]
		if stored.RoleMapping["maintainers"] != "tenant_admin" || stored.RoleMapping["unknown"] != "future-role" || stored.JWKS["keys"].([]any)[0].(map[string]any)["x"] != "public-only" || stored.JWKS["keys"].([]any)[0].(map[string]any)["key_ops"].([]any)[0] != "verify" {
			t.Fatal("provider DTO aliases caller or repository")
		}
	}
}
func TestSSOProviderCommandsValidateBeforeStorageAndReplay(t *testing.T) {
	for _, mutate := range []func(*CreateSSOProviderInput){
		func(in *CreateSSOProviderInput) { in.Name = " " },
		func(in *CreateSSOProviderInput) { in.Type = "OIDC" },
		func(in *CreateSSOProviderInput) { in.Issuer = "http://issuer.example.test" },
		func(in *CreateSSOProviderInput) { in.Issuer = "https://user:private-canary@issuer.example.test" },
		func(in *CreateSSOProviderInput) { in.ClientID = "" },
		func(in *CreateSSOProviderInput) { in.GroupsClaim = "bad\x00" },
		func(in *CreateSSOProviderInput) { in.RoleMapping = map[string]string{"bad\x00": "collector"} },
		func(in *CreateSSOProviderInput) {
			in.RoleMapping = map[string]string{"group": strings.Repeat("x", 65537)}
		},
		func(in *CreateSSOProviderInput) { in.JWKS["keys"].([]any)[0].(map[string]any)["d"] = nil },
		func(in *CreateSSOProviderInput) { in.JWKS["keys"].([]any)[0].(map[string]any)["kid"] = "bad\x00" },
		func(in *CreateSSOProviderInput) { in.SAMLSigningCertificates = []string{"not a certificate"} },
	} {
		f := &ssoProviderFixture{}
		s, a, in := ssoProviderForTest(t, f)
		mutate(&in)
		if out, err := s.CreateSSOProvider(t.Context(), a, in); !errors.Is(err, ErrValidation) || out.ID != "" || f.calls != 0 {
			t.Fatal("invalid provider input reached storage", err)
		}
		if err := s.AuthorizeCreateSSOProvider(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
			t.Fatal("invalid provider input passed replay guard", err)
		}
	}
	for _, grants := range [][]identitydomain.ResourceGrant{nil, {{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"*"}}}, {{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}} {
		f := &ssoProviderFixture{}
		s, a, in := ssoProviderForTest(t, f)
		a.ResourceGrants = grants
		if err := s.AuthorizeCreateSSOProvider(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.calls != 0 {
			t.Fatal("scoped human authority registered provider", err)
		}
	}
}
func TestSSOProviderCommandsPublishNothingAfterFailures(t *testing.T) {
	for _, phase := range []string{"auth", "lock", "write", "audit", "commit", "cancel"} {
		f := &ssoProviderFixture{phase: phase}
		s, a, in := ssoProviderForTest(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		if phase == "cancel" {
			f.cancel = cancel
		}
		out, err := s.CreateSSOProvider(ctx, a, in)
		cancel()
		if err == nil || !reflect.DeepEqual(out, identitydomain.SSOProvider{}) || len(f.providers)+len(f.audits) != 0 {
			t.Fatal("failed provider command published effects", phase, err)
		}
	}
	f := &ssoProviderFixture{}
	s, a, in := ssoProviderForTest(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.CreateSSOProvider(ctx, a, in); !errors.Is(err, context.Canceled) || f.calls != 0 {
		t.Fatal("canceled provider command reached storage", err)
	}
	for _, now := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		s.config.Clock = application.ClockFunc(func() time.Time { return now })
		if out, err := s.CreateSSOProvider(t.Context(), a, in); !errors.Is(err, ErrValidation) || out.ID != "" || len(f.providers)+len(f.audits) != 0 {
			t.Fatal("invalid provider clock published effects", err)
		}
	}
	s.config.Clock = application.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) })
	for _, prefix := range []string{"sso", "ace"} {
		s.config.IDs = application.IDGeneratorFunc(func(p string) string {
			if p == prefix {
				return "bad\x00"
			}
			return p + "_valid"
		})
		if out, err := s.CreateSSOProvider(t.Context(), a, in); !errors.Is(err, ErrValidation) || out.ID != "" || len(f.providers)+len(f.audits) != 0 {
			t.Fatal("invalid generated provider identity published effects", err)
		}
	}
}

func TestSSOProviderCommandsRequireDependenciesAndBoundEveryMetadataField(t *testing.T) {
	f := &ssoProviderFixture{}
	s, a, in := ssoProviderForTest(t, f)
	for _, missing := range []string{"transactions", "authorizer", "trust", "hasher", "clock", "ids"} {
		config := s.config
		switch missing {
		case "transactions":
			config.Transactions = nil
		case "authorizer":
			config.Authorizer = nil
		case "trust":
			config.TrustMaterial = nil
		case "hasher":
			config.Hasher = nil
		case "clock":
			config.Clock = nil
		case "ids":
			config.IDs = nil
		}
		if c, err := NewSSOProviderCommands(config); !errors.Is(err, ErrValidation) || c != nil {
			t.Fatal("missing provider dependency accepted", missing, err)
		}
	}
	//nolint:staticcheck // Prove nil context rejection before storage.
	if _, err := s.CreateSSOProvider(nil, a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
		t.Fatal("nil provider context reached storage", err)
	}
	var absent *SSOProviderCommands
	if _, err := absent.CreateSSOProvider(t.Context(), a, in); !errors.Is(err, ErrValidation) {
		t.Fatal("nil provider service accepted", err)
	}
	for _, field := range []struct {
		max int
		set func(*CreateSSOProviderInput, string)
	}{
		{65536, func(in *CreateSSOProviderInput, v string) { in.Name = v }},
		{128, func(in *CreateSSOProviderInput, v string) { in.Type = v }},
		{65536, func(in *CreateSSOProviderInput, v string) { in.Issuer = v }},
		{65536, func(in *CreateSSOProviderInput, v string) { in.ClientID = v }},
		{65536, func(in *CreateSSOProviderInput, v string) { in.GroupsClaim = v }},
	} {
		for _, bad := range []string{"bad\x00", string([]byte{0xff}), strings.Repeat("x", field.max+1)} {
			copy := in
			field.set(&copy, bad)
			if _, err := s.CreateSSOProvider(t.Context(), a, copy); !errors.Is(err, ErrValidation) || f.calls != 0 {
				t.Fatal("unsafe provider field reached storage", err)
			}
		}
	}
	for _, bad := range []map[string]string{{"bad\x00": "collector"}, {"group": string([]byte{0xff})}, {strings.Repeat("x", 65536): "future-role"}} {
		copy := in
		copy.RoleMapping = bad
		if _, err := s.CreateSSOProvider(t.Context(), a, copy); !errors.Is(err, ErrValidation) || f.calls != 0 {
			t.Fatal("unsafe or oversized role metadata reached storage", err)
		}
	}
	for _, id := range []string{"", " padded ", "bad\x00", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		want := error(ErrValidation)
		if id == "" {
			want = application.ErrUnauthorized
		}
		keyActor := identitydomain.Actor{TenantID: id, KeyID: "key", Scopes: []string{ScopeIdentityAdmin}}
		if _, err := s.CreateSSOProvider(t.Context(), keyActor, in); !errors.Is(err, want) || f.calls != 0 {
			t.Fatal("unsafe provider tenant reached storage", err)
		}
		keyActor.TenantID, keyActor.KeyID = "tenant", id
		if _, err := s.CreateSSOProvider(t.Context(), keyActor, in); !errors.Is(err, want) || f.calls != 0 {
			t.Fatal("unsafe provider actor reached storage", err)
		}
	}
}
