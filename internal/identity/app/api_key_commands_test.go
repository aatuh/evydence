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

type apiKeyCommandFixture struct {
	keys                    []identitydomain.APIKey
	audits                  []application.AuditEvent
	phase                   string
	transactions, generated int
}

func (f *apiKeyCommandFixture) ExecuteAPIKey(ctx context.Context, tenant string, fn func(context.Context, APIKeyTransaction) error) error {
	f.transactions++
	if tenant != "tenant" {
		return ErrNotFound
	}
	if f.phase == "lock" {
		return errors.New("storage failure")
	}
	staged := &apiKeyCommandFixture{phase: f.phase}
	if err := fn(ctx, staged); err != nil {
		return err
	}
	if f.phase == "commit" {
		return errors.New("commit failure")
	}
	f.keys = append(f.keys, staged.keys...)
	f.audits = append(f.audits, staged.audits...)
	return nil
}
func (f *apiKeyCommandFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.phase == "authorization" {
		return application.ErrForbidden
	}
	return NewAPIKeyWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *apiKeyCommandFixture) InsertAPIKey(_ context.Context, k identitydomain.APIKey) error {
	if f.phase == "key" {
		return errors.New("storage failure")
	}
	f.keys = append(f.keys, k)
	return nil
}
func (f *apiKeyCommandFixture) AppendAudit(_ context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errors.New("storage failure")
	}
	f.audits = append(f.audits, a)
	return application.AuditReceipt{}, nil
}
func (f *apiKeyCommandFixture) Generate() (Credential, error) {
	f.generated++
	if f.phase == "credential" {
		return Credential{}, errors.New("entropy failure")
	}
	c, err := NewHMACAuthenticationCredentials("test-pepper")
	if err != nil {
		return Credential{}, err
	}
	return c.Generate()
}
func apiKeyCommandsForTest(t *testing.T, f *apiKeyCommandFixture) (*APIKeyCommands, identitydomain.Actor) {
	t.Helper()
	s, err := NewAPIKeyCommands(APIKeyCommandConfig{Transactions: f, Credentials: f, Authorizer: NewAPIKeyWriteAuthorizer(), Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 2, 3, 4, 123456789, time.FixedZone("test", 3600)) }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	return s, identitydomain.Actor{TenantID: "tenant", KeyID: "admin", Scopes: []string{"*"}}
}

func TestAPIKeyCommandsPreserveScopesCloneInputsAndCommitPrivateCredentialAtomically(t *testing.T) {
	f := &apiKeyCommandFixture{}
	s, a := apiKeyCommandsForTest(t, f)
	expires := time.Date(2025, 9, 1, 1, 2, 3, 456789123, time.FixedZone("test", -3600))
	in := CreateAPIKeyInput{Name: " Automation ", Scopes: []string{" evidence:read ", " ", "evidence:read", "custom:scope"}, ExpiresAt: &expires}
	if err := s.AuthorizeCreateAPIKey(t.Context(), a, in); err != nil || f.generated != 0 || len(f.keys) != 0 {
		t.Fatal("guard issued a credential", err)
	}
	k, secret, err := s.CreateAPIKey(t.Context(), a, in)
	if err != nil || secret == "" || k.Hash != "" || k.Name != "Automation" || k.TenantID != a.TenantID || k.ID != "key_new" || len(f.keys) != 1 || len(f.audits) != 1 {
		t.Fatal("credential contract or atomic effects changed", err)
	}
	want := []string{"", "custom:scope", "evidence:read", "evidence:read"}
	if !reflect.DeepEqual(k.Scopes, want) || !reflect.DeepEqual(f.keys[0].Scopes, want) {
		t.Fatal("legacy normalized scopes changed")
	}
	c, err := NewHMACAuthenticationCredentials("test-pepper")
	if err != nil || f.keys[0].Hash != c.Hash(secret) || f.keys[0].Prefix != c.Prefix(secret) || f.keys[0].Hash == secret {
		t.Fatal("stored credential incompatible or raw", err)
	}
	if k.CreatedAt.Location() != time.UTC || k.CreatedAt.Nanosecond()%1000 != 0 || k.ExpiresAt == nil || k.ExpiresAt.Location() != time.UTC || k.ExpiresAt.Nanosecond()%1000 != 0 || !k.ExpiresAt.Equal(expires.UTC().Truncate(time.Microsecond)) {
		t.Fatal("timestamp precision changed")
	}
	in.Scopes[0] = "mutated"
	expires = expires.Add(time.Hour)
	k.Scopes[0] = "response mutation"
	*k.ExpiresAt = k.ExpiresAt.Add(time.Hour)
	if f.keys[0].Scopes[0] != "" || f.keys[0].ExpiresAt.Equal(*k.ExpiresAt) {
		t.Fatal("stored credential aliases request or response")
	}
	if f.audits[0].EntryType != "api_key.created" || f.audits[0].SubjectID != k.ID || f.audits[0].ActorType != "api_key" || f.audits[0].ActorID != a.KeyID {
		t.Fatal("credential audit incorrect")
	}
}

func TestAPIKeyCommandsRejectInvalidInputsAndExplicitInstanceEscalationBeforeStorage(t *testing.T) {
	for _, in := range []CreateAPIKeyInput{
		{Name: " ", Scopes: []string{"*"}}, {Name: strings.Repeat("x", 65537), Scopes: []string{"*"}}, {Name: "bad\x00", Scopes: []string{"*"}}, {Name: string([]byte{0xff}), Scopes: []string{"*"}},
		{Name: "Key"}, {Name: "Key", Scopes: make([]string, 1025)}, {Name: "Key", Scopes: []string{strings.Repeat("x", 129)}}, {Name: "Key", Scopes: []string{"bad\x00"}}, {Name: "Key", Scopes: []string{string([]byte{0xff})}},
		{Name: "Key", Scopes: []string{"instance:admin"}}, {Name: "Key", Scopes: []string{" instance:admin "}},
	} {
		f := &apiKeyCommandFixture{}
		s, a := apiKeyCommandsForTest(t, f)
		if k, secret, err := s.CreateAPIKey(t.Context(), a, in); err == nil || k.ID != "" || secret != "" || f.transactions != 0 || f.generated != 0 {
			t.Fatal("invalid input reached credential storage")
		}
		if err := s.AuthorizeCreateAPIKey(t.Context(), a, in); err == nil || f.transactions != 0 {
			t.Fatal("invalid replay guard reached storage")
		}
	}
	f := &apiKeyCommandFixture{}
	s, a := apiKeyCommandsForTest(t, f)
	a.Scopes = append(a.Scopes, "instance:admin")
	if _, _, err := s.CreateAPIKey(t.Context(), a, CreateAPIKeyInput{Name: "Instance", Scopes: []string{"instance:admin"}}); err != nil {
		t.Fatal("explicit authority cannot delegate", err)
	}
}

func TestAPIKeyCommandsDenyWrongAuthorityAndPublishNothingAfterFailure(t *testing.T) {
	for _, phase := range []string{"authorization", "lock", "credential", "key", "audit", "commit"} {
		f := &apiKeyCommandFixture{phase: phase}
		s, a := apiKeyCommandsForTest(t, f)
		if k, secret, err := s.CreateAPIKey(t.Context(), a, CreateAPIKeyInput{Name: "Key", Scopes: []string{"evidence:read"}}); err == nil || k.ID != "" || secret != "" || len(f.keys)+len(f.audits) != 0 {
			t.Fatal("failed issuance disclosed partial effects", phase)
		}
	}
	f := &apiKeyCommandFixture{}
	s, a := apiKeyCommandsForTest(t, f)
	a.KeyID, a.UserID = "", "human"
	in := CreateAPIKeyInput{Name: "Key", Scopes: []string{"*"}}
	for _, grants := range [][]identitydomain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}, {{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"*"}}}} {
		a.ResourceGrants = grants
		if _, secret, err := s.CreateAPIKey(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || secret != "" || f.transactions != 0 {
			t.Fatal("foreign or removed grant issued credentials", err)
		}
	}
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}
	if _, _, err := s.CreateAPIKey(t.Context(), a, in); err != nil || f.audits[0].ActorType != "human_user" || f.audits[0].ActorID != "human" {
		t.Fatal("human issuance or audit rejected", err)
	}
}

type apiKeyCredentialFunc func() (Credential, error)

func (f apiKeyCredentialFunc) Generate() (Credential, error) { return f() }

func TestAPIKeyCommandsFailClosedForCancellationInvalidWiringAndCredentialMaterial(t *testing.T) {
	f := &apiKeyCommandFixture{}
	s, a := apiKeyCommandsForTest(t, f)
	in := CreateAPIKeyInput{Name: "Key", Scopes: []string{"evidence:read"}}
	for _, change := range []func(*APIKeyCommandConfig){
		func(c *APIKeyCommandConfig) { c.Transactions = nil }, func(c *APIKeyCommandConfig) { c.Credentials = nil }, func(c *APIKeyCommandConfig) { c.Authorizer = nil }, func(c *APIKeyCommandConfig) { c.Clock = nil }, func(c *APIKeyCommandConfig) { c.IDs = nil },
	} {
		cfg := s.config
		change(&cfg)
		if v, err := NewAPIKeyCommands(cfg); !errors.Is(err, ErrValidation) || v != nil {
			t.Fatal("incomplete credential service accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if k, secret, err := s.CreateAPIKey(ctx, a, in); err == nil || k.ID != "" || secret != "" || f.transactions != 0 {
			t.Fatal("invalid context reached credential storage")
		}
		if err := s.AuthorizeCreateAPIKey(ctx, a, in); err == nil || f.transactions != 0 {
			t.Fatal("invalid guard context reached storage")
		}
	}
	for _, id := range []string{" tenant", "tenant\x00", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		bad := a
		bad.TenantID = id
		if _, secret, err := s.CreateAPIKey(t.Context(), bad, in); !errors.Is(err, ErrValidation) || secret != "" || f.transactions != 0 {
			t.Fatal("bad actor identity reached storage")
		}
	}
	for _, year := range []int{0, 10000} {
		expires := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
		bad := in
		bad.ExpiresAt = &expires
		if _, secret, err := s.CreateAPIKey(t.Context(), a, bad); !errors.Is(err, ErrValidation) || secret != "" || f.transactions != 0 {
			t.Fatal("unserializable expiry reached storage")
		}
	}
	for _, kind := range []string{"empty", "short-secret", "bad-base64", "full-secret-prefix", "bad-hash"} {
		f := &apiKeyCommandFixture{}
		s, a := apiKeyCommandsForTest(t, f)
		s.config.Credentials = apiKeyCredentialFunc(func() (Credential, error) {
			c, err := f.Generate()
			if err != nil {
				return c, err
			}
			switch kind {
			case "empty":
				c = Credential{}
			case "short-secret":
				c.Secret = "evy_short"
			case "bad-base64":
				c.Secret = "evy_" + strings.Repeat("!", 43)
				c.Prefix = c.Secret[:12]
			case "full-secret-prefix":
				c.Prefix = c.Secret
			case "bad-hash":
				c.Hash = strings.Repeat("z", 64)
			}
			return c, nil
		})
		if k, secret, err := s.CreateAPIKey(t.Context(), a, in); !errors.Is(err, ErrValidation) || k.ID != "" || secret != "" || len(f.keys)+len(f.audits) != 0 {
			t.Fatal("invalid credential material published", kind)
		}
	}
	for _, clock := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		f := &apiKeyCommandFixture{}
		s, a := apiKeyCommandsForTest(t, f)
		s.config.Clock = application.ClockFunc(func() time.Time { return clock })
		if _, secret, err := s.CreateAPIKey(t.Context(), a, in); !errors.Is(err, ErrValidation) || secret != "" || f.generated != 0 {
			t.Fatal("invalid clock generated a credential")
		}
	}
	for _, badPrefix := range []string{"key", "ace"} {
		f := &apiKeyCommandFixture{}
		s, a := apiKeyCommandsForTest(t, f)
		s.config.IDs = application.IDGeneratorFunc(func(p string) string {
			if p == badPrefix {
				return ""
			}
			return p + "_valid"
		})
		if _, secret, err := s.CreateAPIKey(t.Context(), a, in); !errors.Is(err, ErrValidation) || secret != "" || len(f.keys)+len(f.audits) != 0 {
			t.Fatal("invalid generated identity committed")
		}
	}
}
