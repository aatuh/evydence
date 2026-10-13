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

type samlBindingCommandFixture struct {
	ssoProviderFixture
	binding *identitydomain.SAMLProviderBinding
	writes  int
}

func (f *samlBindingCommandFixture) ExecuteSAMLProviderBinding(ctx context.Context, fn func(context.Context, SAMLProviderBindingTransaction) error) error {
	f.calls++
	staged := &samlBindingCommandFixture{ssoProviderFixture: ssoProviderFixture{phase: f.phase, cancel: f.cancel}}
	if f.current != nil {
		p := cloneSSOProvider(*f.current)
		staged.current = &p
	}
	if f.binding != nil {
		b := cloneSAMLProviderBinding(*f.binding)
		staged.binding = &b
	}
	if err := fn(ctx, staged); err != nil {
		return err
	}
	if f.phase == "commit" {
		return errors.New("fixture binding commit failure")
	}
	f.binding, f.writes = staged.binding, f.writes+staged.writes
	f.audits = append(f.audits, staged.audits...)
	return nil
}
func (f *samlBindingCommandFixture) UpsertSAMLProviderBinding(_ context.Context, b identitydomain.SAMLProviderBinding) error {
	if f.phase == "write" {
		return ErrConflict
	}
	f.writes++
	b = cloneSAMLProviderBinding(b)
	f.binding = &b
	return nil
}
func (f *samlBindingCommandFixture) ReadOwnedSAMLProviderBinding(context.Context, string, string) (identitydomain.SAMLProviderBinding, error) {
	if f.binding == nil {
		return identitydomain.SAMLProviderBinding{}, ErrNotFound
	}
	return cloneSAMLProviderBinding(*f.binding), nil
}
func samlBindingCommandsForTest(t *testing.T) (*SAMLProviderBindingCommands, *samlBindingCommandFixture, identitydomain.Actor) {
	t.Helper()
	_, request, _ := samlRequestCommandsForTest(t)
	p := cloneSSOProvider(request.binding.Provider)
	f := &samlBindingCommandFixture{ssoProviderFixture: ssoProviderFixture{current: &p}}
	c, err := NewSAMLProviderBindingCommands(SAMLProviderBindingCommandConfig{Transactions: f, Authorizer: NewMembershipWriteAuthorizer(), Hasher: ssoProviderTestHasher{}, Clock: application.ClockFunc(func() time.Time { return request.now }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_binding" })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "operator", Scopes: []string{ScopeIdentityAdmin}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{ScopeIdentityAdmin}}}}
	return c, f, a
}

func TestSAMLBindingCommandsCommitOwnedConfigurationAndAudit(t *testing.T) {
	c, f, a := samlBindingCommandsForTest(t)
	in := ConfigureSAMLProviderBindingInput{Recipient: "https://sp.example.test/v1/sso/session-exchanges"}
	b, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "provider", in)
	if err != nil || f.binding == nil || f.writes != 1 || len(f.audits) != 1 || b.TenantID != a.TenantID || b.ProviderID != "provider" || b.Recipient != in.Recipient || b.NameIDFormat != identitydomain.SAMLNameIDUnspecified || !ValidSAMLProviderBinding(b) {
		t.Fatal("binding did not commit configured owner and defaults", err)
	}
	audit := f.audits[0]
	if audit.EntryType != "sso_provider.saml_binding_configured" || audit.SubjectID != b.ProviderID || audit.TenantID != a.TenantID || audit.ActorID != a.UserID || audit.PayloadHash == "" || !audit.OccurredAt.Equal(b.UpdatedAt) {
		t.Fatal("binding audit lost ownership, time or commitment")
	}
	if err := c.AuthorizeConfigureSAMLProviderBinding(t.Context(), a, "provider", in); err != nil || f.writes != 1 || len(f.audits) != 1 {
		t.Fatal("binding replay authorization emitted effects", err)
	}
	got, err := c.GetSAMLProviderBinding(t.Context(), a, "provider")
	if err != nil || !reflect.DeepEqual(got, b) || f.writes != 1 || len(f.audits) != 1 {
		t.Fatal("binding read changed configuration", err)
	}
	b.Provider.SAMLSigningCertificates[0] = "mutated response"
	got.Provider.SAMLSigningCertificates[0] = "mutated read"
	if f.binding.Provider.SAMLSigningCertificates[0] != "fixture-public-certificate" {
		t.Fatal("binding response aliases stored trust")
	}
}

func TestSAMLBindingCommandsEnforceTenantAdminAndOwnedProvider(t *testing.T) {
	for _, scenario := range []string{"member", "product admin", "wrong tenant", "foreign provider", "oidc provider", "inactive provider", "missing trust", "stale authority"} {
		t.Run(scenario, func(t *testing.T) {
			c, f, a := samlBindingCommandsForTest(t)
			want := application.ErrForbidden
			switch scenario {
			case "member":
				a.Scopes = []string{"evidence:read"}
			case "product admin":
				a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{ScopeIdentityAdmin}}}
			case "wrong tenant":
				a.TenantID = "foreign"
			case "foreign provider":
				f.current.TenantID = "foreign"
				want = ErrNotFound
			case "oidc provider":
				f.current.Type = "oidc"
				want = ErrValidation
			case "inactive provider":
				f.current.Status = "inactive"
				want = ErrValidation
			case "missing trust":
				f.current.SAMLSigningCertificates = nil
				want = ErrValidation
			case "stale authority":
				f.phase = "auth"
			}
			in := ConfigureSAMLProviderBindingInput{Recipient: "https://sp.example.test/consume"}
			if b, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "provider", in); !errors.Is(err, want) || !reflect.DeepEqual(b, identitydomain.SAMLProviderBinding{}) || f.writes != 0 || len(f.audits) != 0 {
				t.Fatal("unauthorized binding changed authority", err)
			}
			if err := c.AuthorizeConfigureSAMLProviderBinding(t.Context(), a, "provider", in); !errors.Is(err, want) {
				t.Fatal("replay guard omitted current authorization/ownership", err)
			}
		})
	}
}

func TestSAMLBindingCommandsValidateBeforeStorage(t *testing.T) {
	for _, in := range []ConfigureSAMLProviderBindingInput{{}, {Recipient: "http://sp.example.test/consume"}, {Recipient: "https://sp.example.test/consume?return=foreign"}, {Recipient: "https://sp.example.test/consume#fragment"}, {Recipient: "https://private@sp.example.test/consume"}, {Recipient: "https://sp.example.test/consume", NameIDFormat: "unknown"}} {
		c, f, a := samlBindingCommandsForTest(t)
		if _, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "provider", in); !errors.Is(err, ErrValidation) || f.calls != 0 {
			t.Fatal("invalid binding reached persistence", err)
		}
	}
	c, f, a := samlBindingCommandsForTest(t)
	if _, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "bad\x00", ConfigureSAMLProviderBindingInput{Recipient: "https://sp.example.test/consume"}); !errors.Is(err, ErrValidation) || f.calls != 0 {
		t.Fatal("invalid provider reached persistence", err)
	}
}

func TestSAMLBindingCommandsRollbackAllConfigurationAndAuditEffects(t *testing.T) {
	for _, phase := range []string{"lock", "read", "write", "audit", "commit", "cancel"} {
		c, f, a := samlBindingCommandsForTest(t)
		f.phase = phase
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		if phase == "cancel" {
			f.cancel = cancel
		}
		if b, err := c.ConfigureSAMLProviderBinding(ctx, a, "provider", ConfigureSAMLProviderBindingInput{Recipient: "https://sp.example.test/consume"}); err == nil || !reflect.DeepEqual(b, identitydomain.SAMLProviderBinding{}) || f.binding != nil || f.writes != 0 || len(f.audits) != 0 {
			t.Fatal("failed binding published partial configuration", phase, err)
		}
	}
}

func TestSAMLBindingCommandsConcealForeignBindingReads(t *testing.T) {
	c, f, a := samlBindingCommandsForTest(t)
	_, request, _ := samlRequestCommandsForTest(t)
	b := cloneSAMLProviderBinding(request.binding)
	b.TenantID, b.Provider.TenantID = "foreign", "foreign"
	f.binding = &b
	if out, err := c.GetSAMLProviderBinding(t.Context(), a, "provider"); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(out, identitydomain.SAMLProviderBinding{}) {
		t.Fatal("foreign binding read leaked configuration", err)
	}
	a.ResourceGrants = nil
	if _, err := c.GetSAMLProviderBinding(t.Context(), a, "provider"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("binding read omitted admin policy", err)
	}
}

func TestSAMLBindingCommandsRejectProviderClaimsOutsideRequestStorageBounds(t *testing.T) {
	for _, field := range []string{"issuer", "audience", "invalid UTF-8", "NUL"} {
		c, f, a := samlBindingCommandsForTest(t)
		switch field {
		case "issuer":
			f.current.Issuer = strings.Repeat("i", 4097)
		case "audience":
			f.current.ClientID = strings.Repeat("a", 4097)
		case "invalid UTF-8":
			f.current.Issuer = "https://idp.example.test/\xff"
		case "NUL":
			f.current.ClientID = "sp\x00"
		}
		if _, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "provider", ConfigureSAMLProviderBindingInput{Recipient: "https://sp.example.test/consume"}); !errors.Is(err, ErrValidation) || f.writes != 0 || len(f.audits) != 0 {
			t.Fatal("unrepresentable provider claim configured login state", field, err)
		}
	}
}
