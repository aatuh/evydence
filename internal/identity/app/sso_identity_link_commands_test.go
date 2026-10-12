package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type identityLinkFixture struct {
	links  []identitydomain.UserIdentityLink
	audits []application.AuditEvent
	calls  int
	phase  string
	cancel context.CancelFunc
}

func (f *identityLinkFixture) ExecuteSSOIdentityLink(ctx context.Context, fn func(context.Context, SSOIdentityLinkTransaction) error) error {
	f.calls++
	staged := &identityLinkFixture{phase: f.phase, cancel: f.cancel}
	if err := fn(ctx, staged); err != nil {
		return err
	}
	if f.phase == "commit" {
		return errors.New("private link commit")
	}
	f.links = append(f.links, staged.links...)
	f.audits = append(f.audits, staged.audits...)
	return nil
}
func (f *identityLinkFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.phase == "auth" {
		return application.ErrForbidden
	}
	return NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *identityLinkFixture) LockSSOIdentityLinkWrites(context.Context, string) error {
	if f.phase == "lock" {
		return errors.New("private link lock")
	}
	return nil
}
func (f *identityLinkFixture) ValidateSSOIdentityLinkTargets(_ context.Context, tenant, user, provider, email string) error {
	if tenant != "tenant" || user != "user" || provider != "provider" || email != "person@example.test" {
		return ErrNotFound
	}
	if f.phase == "parents" {
		return errors.New("private link parents")
	}
	return nil
}
func (f *identityLinkFixture) InsertUserIdentityLink(_ context.Context, v identitydomain.UserIdentityLink) error {
	if f.phase == "write" {
		return ErrConflict
	}
	f.links = append(f.links, v)
	return nil
}
func (f *identityLinkFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errors.New("private link audit")
	}
	f.audits = append(f.audits, v)
	if f.cancel != nil {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func identityLinkForTest(t *testing.T, f *identityLinkFixture) (*SSOIdentityLinkCommands, identitydomain.Actor, LinkSSOIdentityInput) {
	t.Helper()
	s, err := NewSSOIdentityLinkCommands(SSOIdentityLinkCommandConfig{Transactions: f, Authorizer: NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 1, 2, 3, 123456789, time.FixedZone("fixture", 3600)) }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "operator", Scopes: []string{"identity:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"identity:admin"}}}}
	return s, a, LinkSSOIdentityInput{UserID: " user ", ProviderID: " provider ", Subject: " Subject-1 ", Email: " PERSON@example.test ", Verified: true}
}
func TestSSOIdentityLinkCommandsPreserveMetadataAuditAndReadOnlyGuard(t *testing.T) {
	f := &identityLinkFixture{}
	s, a, in := identityLinkForTest(t, f)
	if err := s.AuthorizeLinkSSOIdentity(t.Context(), a, in); err != nil || len(f.links)+len(f.audits) != 0 {
		t.Fatal("link guard emitted effects", err)
	}
	v, err := s.LinkSSOIdentity(t.Context(), a, in)
	if err != nil || v.TenantID != a.TenantID || v.UserID != "user" || v.ProviderID != "provider" || v.Subject != "Subject-1" || v.Email != "person@example.test" || !v.Verified || v.SchemaVersion != "user-identity-link.v1.0.0" || v.CreatedAt.Location() != time.UTC || v.CreatedAt.Nanosecond()%1000 != 0 || len(f.links) != 1 || len(f.audits) != 1 {
		t.Fatal("link metadata contract changed", err)
	}
	audit := f.audits[0]
	if audit.EntryType != "identity_link.created" || audit.SubjectType != "human_user" || audit.SubjectID != v.UserID || audit.ActorID != a.UserID || audit.ActorType != "human_user" || audit.OccurredAt != v.CreatedAt || audit.PayloadHash != "" {
		t.Fatal("link audit attribution changed")
	}
}
func TestSSOIdentityLinkCommandsRejectUnsafeInputAndWrongAuthorityBeforeStorage(t *testing.T) {
	for _, field := range []struct {
		name string
		max  int
		set  func(*LinkSSOIdentityInput, string)
	}{
		{"user", 1024, func(in *LinkSSOIdentityInput, v string) { in.UserID = v }},
		{"provider", 1024, func(in *LinkSSOIdentityInput, v string) { in.ProviderID = v }},
		{"subject", MaxMembershipKeyBytes, func(in *LinkSSOIdentityInput, v string) { in.Subject = v }},
		{"email", MaxMembershipKeyBytes, func(in *LinkSSOIdentityInput, v string) { in.Email = v }},
	} {
		for _, bad := range []string{"", " ", "bad\x00", string([]byte{0xff}), strings.Repeat("x", field.max+1)} {
			f := &identityLinkFixture{}
			s, a, in := identityLinkForTest(t, f)
			field.set(&in, bad)
			if _, err := s.LinkSSOIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
				t.Fatal("unsafe link text reached storage", field.name, err)
			}
		}
	}
	f := &identityLinkFixture{}
	s, a, in := identityLinkForTest(t, f)
	in.Verified = false
	if _, err := s.LinkSSOIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
		t.Fatal("unverified link reached storage", err)
	}
	in.Verified = true
	in.Subject = strings.Repeat("x", MaxMembershipKeyBytes-len(a.TenantID)-len("provider")+1)
	if _, err := s.LinkSSOIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
		t.Fatal("oversized unique identity reached storage", err)
	}
	in.Subject = "subject"
	for _, grants := range [][]identitydomain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}, {{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"*"}}}} {
		a.ResourceGrants = grants
		if _, err := s.LinkSSOIdentity(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.calls != 0 {
			t.Fatal("scoped link authority became tenant-wide", err)
		}
	}
}
func TestSSOIdentityLinkCommandsParentsAndAllFailuresPublishNothing(t *testing.T) {
	for _, stage := range []string{"auth", "lock", "parents", "write", "audit", "commit", "cancel"} {
		f := &identityLinkFixture{phase: stage}
		s, a, in := identityLinkForTest(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		if stage == "cancel" {
			f.cancel = cancel
		}
		out, err := s.LinkSSOIdentity(ctx, a, in)
		cancel()
		if err == nil || out != (identitydomain.UserIdentityLink{}) || len(f.links)+len(f.audits) != 0 {
			t.Fatal("failed link published effects", stage, err)
		}
	}
	for _, field := range []string{"user", "provider", "email"} {
		f := &identityLinkFixture{}
		s, a, in := identityLinkForTest(t, f)
		switch field {
		case "user":
			in.UserID = "other"
		case "provider":
			in.ProviderID = "other"
		case "email":
			in.Email = "other@example.test"
		}
		if _, err := s.LinkSSOIdentity(t.Context(), a, in); !errors.Is(err, ErrNotFound) || len(f.links)+len(f.audits) != 0 {
			t.Fatal("foreign link target accepted", field, err)
		}
	}
	f := &identityLinkFixture{}
	s, a, in := identityLinkForTest(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.LinkSSOIdentity(ctx, a, in); !errors.Is(err, context.Canceled) || f.calls != 0 {
		t.Fatal("canceled link reached storage", err)
	}
	for _, prefix := range []string{"uil", "ace"} {
		f := &identityLinkFixture{}
		s, a, in := identityLinkForTest(t, f)
		s.config.IDs = application.IDGeneratorFunc(func(p string) string {
			if p == prefix {
				return "bad\x00"
			}
			return p + "_valid"
		})
		if v, err := s.LinkSSOIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || len(f.links)+len(f.audits) != 0 {
			t.Fatal("invalid generated link identity retained", prefix, err)
		}
	}
}

func TestSSOIdentityLinkCommandsValidateDependenciesClockAndCanonicalIdentity(t *testing.T) {
	f := &identityLinkFixture{}
	s, a, in := identityLinkForTest(t, f)
	for _, missing := range []string{"transactions", "authorizer", "clock", "ids"} {
		config := s.config
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
		if command, err := NewSSOIdentityLinkCommands(config); !errors.Is(err, ErrValidation) || command != nil {
			t.Fatal("missing link dependency accepted", missing, err)
		}
	}
	//nolint:staticcheck // Intentionally exercise nil-context rejection.
	if _, err := s.LinkSSOIdentity(nil, a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
		t.Fatal("nil link context reached storage", err)
	}
	var absent *SSOIdentityLinkCommands
	if _, err := absent.LinkSSOIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) {
		t.Fatal("nil link command accepted", err)
	}
	for _, now := range []time.Time{{}, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		f := &identityLinkFixture{}
		s, a, in := identityLinkForTest(t, f)
		s.config.Clock = application.ClockFunc(func() time.Time { return now })
		if v, err := s.LinkSSOIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || len(f.links)+len(f.audits) != 0 {
			t.Fatal("invalid link timestamp published effects", err)
		}
	}
	for _, bad := range []string{"", " padded ", "bad\x00", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		for _, prefix := range []string{"uil", "ace"} {
			f := &identityLinkFixture{}
			s, a, in := identityLinkForTest(t, f)
			s.config.IDs = application.IDGeneratorFunc(func(p string) string {
				if p == prefix {
					return bad
				}
				return p + "_valid"
			})
			if v, err := s.LinkSSOIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || len(f.links)+len(f.audits) != 0 {
				t.Fatal("invalid link identity published effects", prefix, err)
			}
		}
	}
	for _, email := range []string{"not-email", "Person <person@example.test>", "person@example.test,second@example.test"} {
		f := &identityLinkFixture{}
		s, a, in := identityLinkForTest(t, f)
		in.Email = email
		if _, err := s.LinkSSOIdentity(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
			t.Fatal("non-mailbox link email reached storage", err)
		}
	}
	in.Subject = strings.Repeat("x", MaxMembershipKeyBytes-len(a.TenantID)-len("provider"))
	if v, err := s.LinkSSOIdentity(t.Context(), a, in); err != nil || v.Subject != in.Subject {
		t.Fatal("indexed link identity limit rejected", err)
	}
}
