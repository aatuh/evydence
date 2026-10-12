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

type sessionRevocationFixture struct {
	session                      identitydomain.SSOSession
	phase                        string
	writes, audits, transactions int
	audit                        application.AuditEvent
	cancel                       context.CancelFunc
}

func (f *sessionRevocationFixture) ExecuteSSOSessionRevocation(ctx context.Context, fn func(context.Context, SSOSessionRevocationTransaction) error) error {
	f.transactions++
	staged := *f
	if err := fn(ctx, &staged); err != nil {
		return err
	}
	if f.phase == "commit" {
		return errors.New("private commit failure")
	}
	*f = staged
	return nil
}
func (f *sessionRevocationFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.phase == "auth" {
		return application.ErrForbidden
	}
	return NewSSOSessionRevocationAuthorizer().Authorize(ctx, a, r)
}
func (f *sessionRevocationFixture) LockSSOSessionWrites(context.Context, string) error {
	if f.phase == "lock" {
		return errors.New("private lock failure")
	}
	return nil
}
func (f *sessionRevocationFixture) ReadSSOSessionForRevocation(_ context.Context, tenant, id string) (identitydomain.SSOSession, error) {
	if f.phase == "read" {
		return identitydomain.SSOSession{}, errors.New("private read failure")
	}
	if f.session.TenantID != tenant || f.session.ID != id {
		return identitydomain.SSOSession{}, ErrNotFound
	}
	return cloneSSOSession(f.session), nil
}
func (f *sessionRevocationFixture) RevokeSSOSessionMetadata(_ context.Context, previous identitydomain.SSOSession, now time.Time) error {
	if f.phase == "write" {
		return errors.New("private write failure")
	}
	if previous.Hash != "" || previous.RevokedAt != nil {
		return ErrValidation
	}
	f.session.RevokedAt = &now
	f.writes++
	return nil
}
func (f *sessionRevocationFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errors.New("private audit failure")
	}
	f.audits++
	f.audit = v
	if f.cancel != nil {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func sessionRevocationForTest(t *testing.T, f *sessionRevocationFixture) (*SSOSessionRevocationCommands, identitydomain.Actor) {
	t.Helper()
	now := time.Date(2026, 10, 3, 1, 2, 3, 456789123, time.FixedZone("fixture", 3600))
	f.session = identitydomain.SSOSession{ID: "session", TenantID: "tenant", UserID: "user", ProviderID: "provider", Prefix: "public-prefix", Groups: []string{"maintainers"}, ExpiresAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Hour), SchemaVersion: identitydomain.SSOSessionSchemaVersion}
	c, err := NewSSOSessionRevocationCommands(SSOSessionRevocationConfig{Transactions: f, Authorizer: NewSSOSessionRevocationAuthorizer(), Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, identitydomain.Actor{TenantID: "tenant", UserID: "operator", SessionID: "operator-session", Scopes: []string{ScopeIdentityAdmin}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{ScopeIdentityAdmin}}}}
}
func TestSSOSessionRevocationCommandsAuthorizeCurrentOwnerWithoutEffectsAndRevokeAtomically(t *testing.T) {
	for _, self := range []bool{false, true} {
		f := &sessionRevocationFixture{}
		c, a := sessionRevocationForTest(t, f)
		if self {
			a.UserID = "user"
			a.SessionID = "session"
			a.Scopes = nil
			a.ResourceGrants = nil
		}
		guard := func() error { return c.AuthorizeRevokeSSOSession(t.Context(), a, " session ") }
		run := func() (identitydomain.SSOSession, error) { return c.RevokeSSOSession(t.Context(), a, " session ") }
		if self {
			guard = func() error { return c.AuthorizeRevokeCurrentSSOSession(t.Context(), a) }
			run = func() (identitydomain.SSOSession, error) { return c.RevokeCurrentSSOSession(t.Context(), a) }
		}
		if err := guard(); err != nil || f.writes+f.audits != 0 {
			t.Fatal("revocation guard changed state", self, err)
		}
		v, err := run()
		if err != nil || v.Hash != "" || v.RevokedAt == nil || v.RevokedAt.Location() != time.UTC || v.RevokedAt.Nanosecond()%1000 != 0 || f.writes != 1 || f.audits != 1 || f.audit.EntryType != "sso_session.revoked" || f.audit.SubjectType != "sso_session" || f.audit.SubjectID != v.ID || f.audit.ActorType != "human_user" || f.audit.ActorID != a.UserID || f.audit.OccurredAt != *v.RevokedAt {
			t.Fatal("revocation contract lost", self, err)
		}
		v.Groups[0] = "modified"
		if f.session.Groups[0] != "maintainers" {
			t.Fatal("revocation response aliases stored metadata")
		}
		if err := guard(); err != nil {
			t.Fatal("completed metadata replay denied after revocation", err)
		}
		if _, err := run(); !errors.Is(err, ErrConflict) || f.writes != 1 || f.audits != 1 {
			t.Fatal("new command re-revoked a session", err)
		}
	}
}
func TestSSOSessionRevocationCommandsRejectAuthorityForeignOwnershipAndFailures(t *testing.T) {
	for _, phase := range []string{"auth", "lock", "read", "write", "audit", "commit", "cancel"} {
		f := &sessionRevocationFixture{phase: phase}
		c, a := sessionRevocationForTest(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		if phase == "cancel" {
			f.cancel = cancel
		}
		v, err := c.RevokeSSOSession(ctx, a, "session")
		cancel()
		if err == nil || !reflect.DeepEqual(v, identitydomain.SSOSession{}) || f.writes+f.audits != 0 || f.session.RevokedAt != nil {
			t.Fatal("failed revocation returned output or effects", phase, err)
		}
	}
	for _, bad := range []string{"", " ", "session\x00", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		f := &sessionRevocationFixture{}
		c, a := sessionRevocationForTest(t, f)
		if _, err := c.RevokeSSOSession(t.Context(), a, bad); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal("bad session ID reached database", err)
		}
	}
	f := &sessionRevocationFixture{}
	c, a := sessionRevocationForTest(t, f)
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}
	if _, err := c.RevokeSSOSession(t.Context(), a, "session"); !errors.Is(err, application.ErrForbidden) || f.transactions != 0 {
		t.Fatal("scoped admin revoked a session", err)
	}
	a.UserID = "wrong-user"
	a.SessionID = "session"
	a.Scopes = nil
	a.ResourceGrants = nil
	if _, err := c.RevokeCurrentSSOSession(t.Context(), a); !errors.Is(err, ErrNotFound) || f.writes+f.audits != 0 {
		t.Fatal("logout revoked another user's session", err)
	}
	a.UserID = ""
	a.KeyID = "key"
	if _, err := c.RevokeCurrentSSOSession(t.Context(), a); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("API key logged out a human", err)
	}
	a.UserID = "user"
	a.KeyID = ""
	a.SessionID = "session"
	a.TenantID = "other"
	if _, err := c.RevokeCurrentSSOSession(t.Context(), a); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign tenant session was exposed", err)
	}
}

func TestSSOSessionRevocationCommandsRejectInvalidConfigurationAndMetadata(t *testing.T) {
	f := &sessionRevocationFixture{}
	c, a := sessionRevocationForTest(t, f)
	for _, missing := range []string{"transactions", "authorizer", "clock", "ids"} {
		config := c.config
		switch missing {
		case "transactions":
			config.Transactions = nil
		case "authorizer":
			config.Authorizer = nil
		case "clock":
			config.Clock = nil
		case "ids":
			config.IDs = nil
		}
		if v, err := NewSSOSessionRevocationCommands(config); !errors.Is(err, ErrValidation) || v != nil {
			t.Fatal("invalid revocation configuration accepted", missing, err)
		}
	}
	for _, bad := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		f := &sessionRevocationFixture{}
		c, a := sessionRevocationForTest(t, f)
		c.config.Clock = application.ClockFunc(func() time.Time { return bad })
		if v, err := c.RevokeSSOSession(t.Context(), a, "session"); !errors.Is(err, ErrValidation) || v.ID != "" || f.writes+f.audits != 0 {
			t.Fatal("bad revocation clock committed effects", err)
		}
	}
	for _, field := range []string{"hash", "user", "provider", "created", "expiry"} {
		f := &sessionRevocationFixture{}
		c, a := sessionRevocationForTest(t, f)
		switch field {
		case "hash":
			f.session.Hash = "must-not-cross-port"
		case "user":
			f.session.UserID = ""
		case "provider":
			f.session.ProviderID = "bad\x00"
		case "created":
			f.session.CreatedAt = time.Time{}
		case "expiry":
			f.session.ExpiresAt = time.Time{}
		}
		if v, err := c.RevokeSSOSession(t.Context(), a, "session"); !errors.Is(err, ErrConflict) || v.ID != "" || f.writes+f.audits != 0 {
			t.Fatal("invalid stored metadata reached mutation", field, err)
		}
	}
	c.config.IDs = application.IDGeneratorFunc(func(string) string { return "bad\x00" })
	if v, err := c.RevokeSSOSession(t.Context(), a, "session"); !errors.Is(err, ErrValidation) || v.ID != "" || f.writes+f.audits != 0 {
		t.Fatal("invalid audit identity leaked staged revocation", err)
	}
	//nolint:staticcheck // Explicit nil-context rejection.
	if _, err := c.RevokeSSOSession(nil, a, "session"); !errors.Is(err, ErrValidation) {
		t.Fatal("nil revocation context accepted", err)
	}
	var absent *SSOSessionRevocationCommands
	if _, err := absent.RevokeCurrentSSOSession(t.Context(), a); !errors.Is(err, ErrValidation) {
		t.Fatal("nil revocation service accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.RevokeSSOSession(ctx, a, "session"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled revocation accepted", err)
	}
}
