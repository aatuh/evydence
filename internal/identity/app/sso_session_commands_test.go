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

type sessionCommandFixture struct {
	sessions                  []identitydomain.SSOSession
	audits                    []application.AuditEvent
	phase                     string
	transactions, generations int
	cancel                    context.CancelFunc
	credential                Credential
}

func (f *sessionCommandFixture) ExecuteSSOSession(ctx context.Context, fn func(context.Context, SSOSessionTransaction) error) error {
	f.transactions++
	staged := &sessionCommandFixture{phase: f.phase, cancel: f.cancel}
	if err := fn(ctx, staged); err != nil {
		return err
	}
	if f.phase == "commit" {
		return errors.New("private session commit")
	}
	f.sessions = append(f.sessions, staged.sessions...)
	f.audits = append(f.audits, staged.audits...)
	return nil
}
func (f *sessionCommandFixture) GenerateSession() (Credential, error) {
	f.generations++
	if f.phase == "credentials" {
		return Credential{}, errors.New("private session entropy")
	}
	return f.credential, nil
}
func (f *sessionCommandFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.phase == "auth" {
		return application.ErrForbidden
	}
	return NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *sessionCommandFixture) LockSSOSessionWrites(context.Context, string) error {
	if f.phase == "lock" {
		return errors.New("private session lock")
	}
	return nil
}
func (f *sessionCommandFixture) ValidateSSOSessionTargets(_ context.Context, tenant, user, provider string) error {
	if tenant != "tenant" || user != "user" || provider != "provider" || f.phase == "inactive" {
		return ErrNotFound
	}
	if f.phase == "parents" {
		return errors.New("private session parents")
	}
	return nil
}
func (f *sessionCommandFixture) InsertSSOSession(_ context.Context, v identitydomain.SSOSession) error {
	if f.phase == "write" {
		return errors.New("private session write")
	}
	f.sessions = append(f.sessions, v)
	return nil
}
func (f *sessionCommandFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errors.New("private session audit")
	}
	f.audits = append(f.audits, v)
	if f.cancel != nil {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func sessionCommandsForTest(t *testing.T, f *sessionCommandFixture) (*SSOSessionCommands, identitydomain.Actor, CreateSSOSessionInput) {
	t.Helper()
	secret := "evysso_" + strings.Repeat("A", 43)
	c, err := NewHMACAuthenticationCredentials("fixture-pepper")
	if err != nil {
		t.Fatal(err)
	}
	f.credential = Credential{Secret: secret, Prefix: c.Prefix(secret), Hash: c.Hash(secret)}
	now := time.Date(2026, 9, 1, 1, 2, 3, 123456789, time.FixedZone("fixture", 3600))
	s, err := NewSSOSessionCommands(SSOSessionCommandConfig{Transactions: f, Credentials: f, Authorizer: NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "operator", Scopes: []string{"identity:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"identity:admin"}}}}
	return s, a, CreateSSOSessionInput{UserID: " user ", ProviderID: " provider ", ExpiresAt: now.Add(30 * 24 * time.Hour)}
}
func TestSSOSessionCommandsIssueOnceAfterCommitWithCurrentParentsAndAudit(t *testing.T) {
	f := &sessionCommandFixture{}
	s, a, in := sessionCommandsForTest(t, f)
	if err := s.AuthorizeCreateSSOSession(t.Context(), a, in); err != nil || f.generations != 0 || len(f.sessions)+len(f.audits) != 0 {
		t.Fatal("session guard minted credentials or effects", err)
	}
	v, secret, err := s.CreateSSOSession(t.Context(), a, in)
	if err != nil || secret != f.credential.Secret || v.Hash != "" || v.UserID != "user" || v.ProviderID != "provider" || v.TenantID != a.TenantID || v.SchemaVersion != identitydomain.SSOSessionSchemaVersion || v.ExpiresAt != in.ExpiresAt.UTC().Truncate(time.Microsecond) || v.CreatedAt.Location() != time.UTC || v.CreatedAt.Nanosecond()%1000 != 0 || f.generations != 1 || len(f.sessions) != 1 || f.sessions[0].Hash != f.credential.Hash || len(f.audits) != 1 {
		t.Fatal("session issuance/public DTO contract changed", err)
	}
	audit := f.audits[0]
	if audit.EntryType != "sso_session.created" || audit.SubjectType != "human_user" || audit.SubjectID != v.UserID || audit.ActorType != "human_user" || audit.ActorID != a.UserID || audit.OccurredAt != v.CreatedAt {
		t.Fatal("session audit attribution changed")
	}
	// An elapsed request expiry is not grounds to mint a replacement credential
	// or deny a completed metadata replay. New issuance must still reject it.
	in.ExpiresAt = v.CreatedAt.Add(-time.Hour)
	if err := s.AuthorizeCreateSSOSession(t.Context(), a, in); err != nil || f.generations != 1 {
		t.Fatal("expired replay guard minted a secret or denied metadata", err)
	}
	if _, secret, err := s.CreateSSOSession(t.Context(), a, in); !errors.Is(err, ErrValidation) || secret != "" || f.generations != 1 {
		t.Fatal("expired request minted a session", err)
	}
}
func TestSSOSessionCommandsRejectInputsAuthorityParentsAndDependencyFailures(t *testing.T) {
	for _, bad := range []string{"", " ", "user\x00", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		for _, field := range []string{"user", "provider"} {
			f := &sessionCommandFixture{}
			s, a, in := sessionCommandsForTest(t, f)
			if field == "user" {
				in.UserID = bad
			} else {
				in.ProviderID = bad
			}
			if _, secret, err := s.CreateSSOSession(t.Context(), a, in); !errors.Is(err, ErrValidation) || secret != "" || f.generations+f.transactions != 0 {
				t.Fatal("bad session identity reached storage", field, err)
			}
		}
	}
	for _, phase := range []string{"auth", "lock", "parents", "inactive", "credentials", "write", "audit", "commit", "cancel"} {
		f := &sessionCommandFixture{phase: phase}
		s, a, in := sessionCommandsForTest(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		if phase == "cancel" {
			f.cancel = cancel
		}
		v, secret, err := s.CreateSSOSession(ctx, a, in)
		cancel()
		if err == nil || !reflect.DeepEqual(v, identitydomain.SSOSession{}) || secret != "" || len(f.sessions)+len(f.audits) != 0 {
			t.Fatal("failed session published credential or effects", phase, err)
		}
	}
	f := &sessionCommandFixture{}
	s, a, in := sessionCommandsForTest(t, f)
	for _, grants := range [][]identitydomain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}, {{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"*"}}}} {
		a.ResourceGrants = grants
		if _, secret, err := s.CreateSSOSession(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || secret != "" || f.generations+f.transactions != 0 {
			t.Fatal("scoped human authority issued a session", err)
		}
	}
}

func TestSSOSessionCommandsRejectInvalidDependenciesOutputsAndTimes(t *testing.T) {
	f := &sessionCommandFixture{}
	s, a, in := sessionCommandsForTest(t, f)
	for _, missing := range []string{"transactions", "credentials", "authorizer", "clock", "ids"} {
		config := s.config
		switch missing {
		case "transactions":
			config.Transactions = nil
		case "credentials":
			config.Credentials = nil
		case "authorizer":
			config.Authorizer = nil
		case "clock":
			config.Clock = nil
		case "ids":
			config.IDs = nil
		}
		if v, err := NewSSOSessionCommands(config); !errors.Is(err, ErrValidation) || v != nil {
			t.Fatal("missing session dependency accepted", missing, err)
		}
	}
	for _, bad := range []time.Time{{}, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		f := &sessionCommandFixture{}
		s, a, in := sessionCommandsForTest(t, f)
		in.ExpiresAt = bad
		if _, secret, err := s.CreateSSOSession(t.Context(), a, in); !errors.Is(err, ErrValidation) || secret != "" || f.generations+f.transactions != 0 {
			t.Fatal("invalid session expiry reached storage", err)
		}
		in.ExpiresAt = time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
		s.config.Clock = application.ClockFunc(func() time.Time { return bad })
		if _, secret, err := s.CreateSSOSession(t.Context(), a, in); !errors.Is(err, ErrValidation) || secret != "" || f.generations != 0 {
			t.Fatal("invalid session clock minted credentials", err)
		}
	}
	for _, field := range []string{"secret", "prefix", "hash"} {
		for _, bad := range []string{"", "bad\x00", string([]byte{0xff}), strings.Repeat("x", 65)} {
			f := &sessionCommandFixture{}
			s, a, in := sessionCommandsForTest(t, f)
			switch field {
			case "secret":
				f.credential.Secret = bad
			case "prefix":
				f.credential.Prefix = bad
			case "hash":
				f.credential.Hash = bad
			}
			if v, secret, err := s.CreateSSOSession(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || secret != "" || len(f.sessions)+len(f.audits) != 0 {
				t.Fatal("bad generated session material published", field, err)
			}
		}
	}
	for _, prefix := range []string{"sess", "ace"} {
		f := &sessionCommandFixture{}
		s, a, in := sessionCommandsForTest(t, f)
		s.config.IDs = application.IDGeneratorFunc(func(p string) string {
			if p == prefix {
				return "bad\x00"
			}
			return p + "_valid"
		})
		if v, secret, err := s.CreateSSOSession(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || secret != "" || len(f.sessions)+len(f.audits) != 0 {
			t.Fatal("bad session ID published", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, secret, err := s.CreateSSOSession(ctx, a, in); !errors.Is(err, context.Canceled) || secret != "" || f.generations+f.transactions != 0 {
		t.Fatal("canceled session request reached storage", err)
	}
	//nolint:staticcheck // Explicit nil-context rejection.
	if _, secret, err := s.CreateSSOSession(nil, a, in); !errors.Is(err, ErrValidation) || secret != "" {
		t.Fatal("nil session context accepted", err)
	}
	var absent *SSOSessionCommands
	if _, _, err := absent.CreateSSOSession(t.Context(), a, in); !errors.Is(err, ErrValidation) {
		t.Fatal("nil session command accepted", err)
	}
}
