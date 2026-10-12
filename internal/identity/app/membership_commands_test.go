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

type membershipFixture struct {
	orgs   map[string]identitydomain.Organization
	users  map[string]identitydomain.HumanUser
	audits []application.AuditEvent
	phase  string
	calls  int
	cancel context.CancelFunc
}

func (f *membershipFixture) ExecuteMembership(ctx context.Context, fn func(context.Context, MembershipTransaction) error) error {
	f.calls++
	staged := &membershipFixture{orgs: map[string]identitydomain.Organization{}, users: map[string]identitydomain.HumanUser{}, phase: f.phase, cancel: f.cancel}
	for id, v := range f.orgs {
		staged.orgs[id] = v
	}
	for id, v := range f.users {
		staged.users[id] = cloneHumanUser(v)
	}
	if err := fn(ctx, staged); err != nil {
		return err
	}
	if f.phase == "commit" {
		return errors.New("private commit")
	}
	f.orgs, f.users = staged.orgs, staged.users
	f.audits = append(f.audits, staged.audits...)
	return nil
}
func (f *membershipFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.phase == "auth" {
		return application.ErrForbidden
	}
	return NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *membershipFixture) LockMembershipWrites(context.Context, string) error {
	if f.phase == "lock" {
		return errors.New("private lock")
	}
	return nil
}
func (f *membershipFixture) OrganizationSlugExists(_ context.Context, tenant, slug string) (bool, error) {
	if f.phase == "read" {
		return false, errors.New("private read")
	}
	for _, v := range f.orgs {
		if v.TenantID == tenant && v.Slug == slug {
			return true, nil
		}
	}
	return false, nil
}
func (f *membershipFixture) UserEmailExists(_ context.Context, tenant, email string) (bool, error) {
	if f.phase == "read" {
		return false, errors.New("private read")
	}
	for _, v := range f.users {
		if v.TenantID == tenant && v.Email == email {
			return true, nil
		}
	}
	return false, nil
}
func (f *membershipFixture) ReadMembershipOrganization(_ context.Context, tenant, id string) (MembershipOrganization, error) {
	if f.phase == "read" {
		return MembershipOrganization{}, errors.New("private read")
	}
	v, ok := f.orgs[id]
	if !ok {
		return MembershipOrganization{}, ErrNotFound
	}
	return MembershipOrganization{ID: v.ID, TenantID: v.TenantID}, nil
}
func (f *membershipFixture) ReadMembershipUser(_ context.Context, tenant, id string) (identitydomain.HumanUser, error) {
	if f.phase == "read" {
		return identitydomain.HumanUser{}, errors.New("private read")
	}
	v, ok := f.users[id]
	if !ok {
		return identitydomain.HumanUser{}, ErrNotFound
	}
	return cloneHumanUser(v), nil
}
func (f *membershipFixture) InsertOrganization(_ context.Context, v identitydomain.Organization) error {
	if f.phase == "write" {
		return errors.New("private write")
	}
	f.orgs[v.ID] = v
	return nil
}
func (f *membershipFixture) InsertHumanUser(_ context.Context, v identitydomain.HumanUser) error {
	if f.phase == "write" {
		return errors.New("private write")
	}
	f.users[v.ID] = cloneHumanUser(v)
	return nil
}
func (f *membershipFixture) DeactivateHumanUser(ctx context.Context, v identitydomain.HumanUser) error {
	return f.InsertHumanUser(ctx, v)
}
func (f *membershipFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errors.New("private audit")
	}
	f.audits = append(f.audits, v)
	if f.cancel != nil {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func membershipForTest(t *testing.T, f *membershipFixture) (*MembershipCommands, identitydomain.Actor) {
	t.Helper()
	if f.orgs == nil {
		f.orgs = map[string]identitydomain.Organization{}
	}
	if f.users == nil {
		f.users = map[string]identitydomain.HumanUser{}
	}
	s, err := NewMembershipCommands(MembershipCommandConfig{Transactions: f, Authorizer: NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 1, 2, 3, 123456789, time.FixedZone("test", 3600)) }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	return s, identitydomain.Actor{TenantID: "tenant", UserID: "operator", Scopes: []string{"identity:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"identity:admin"}}}}
}
func TestMembershipCommandsNormalizeOwnRecordsAndCommitAuditAtomically(t *testing.T) {
	f := &membershipFixture{}
	s, a := membershipForTest(t, f)
	o, err := s.CreateOrganization(t.Context(), a, CreateOrganizationInput{Name: " Example ", Slug: " Example "})
	if err != nil || o.Name != "Example" || o.Slug != "Example" || o.Status != "active" || o.TenantID != a.TenantID || o.SchemaVersion != identitydomain.OrganizationSchemaVersion || o.CreatedAt.Location() != time.UTC || o.CreatedAt.Nanosecond()%1000 != 0 {
		t.Fatal("organization contract changed", err)
	}
	in := CreateUserInput{OrganizationID: " " + o.ID + " ", Email: " PERSON@EXAMPLE.TEST ", DisplayName: " Person "}
	u, err := s.CreateUser(t.Context(), a, in)
	if err != nil || u.Email != "person@example.test" || u.DisplayName != "Person" || u.OrganizationID != o.ID || u.TenantID != a.TenantID || u.Status != "active" || u.SchemaVersion != identitydomain.HumanUserSchemaVersion || len(f.audits) != 2 {
		t.Fatal("user contract changed", err)
	}
	if f.audits[0].ActorType != "human_user" || f.audits[0].ActorID != a.UserID || f.audits[0].EntryType != "organization.created" || f.audits[1].EntryType != "user.created" {
		t.Fatal("membership audit attribution lost")
	}
	if err := s.AuthorizeCreateOrganization(t.Context(), a, CreateOrganizationInput{Name: o.Name, Slug: o.Slug}); err != nil {
		t.Fatal("guard blocked own replay", err)
	}
	if err := s.AuthorizeCreateUser(t.Context(), a, in); err != nil {
		t.Fatal("user guard blocked own replay", err)
	}
	if _, err := s.CreateOrganization(t.Context(), a, CreateOrganizationInput{Name: o.Name, Slug: o.Slug}); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate organization accepted", err)
	}
	if _, err := s.CreateUser(t.Context(), a, in); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate normalized email accepted", err)
	}
	deactivated, err := s.DeactivateUser(t.Context(), a, u.ID)
	if err != nil || deactivated.Status != "deactivated" || deactivated.DeactivatedAt == nil || len(f.audits) != 3 || f.audits[2].EntryType != "user.deactivated" {
		t.Fatal("deactivation did not commit", err)
	}
	*deactivated.DeactivatedAt = deactivated.DeactivatedAt.Add(time.Hour)
	if f.users[u.ID].DeactivatedAt.Equal(*deactivated.DeactivatedAt) {
		t.Fatal("deactivation response aliases stored state")
	}
	if err := s.AuthorizeDeactivateUser(t.Context(), a, u.ID); err != nil {
		t.Fatal("deactivation guard blocked completed replay", err)
	}
	if _, err := s.DeactivateUser(t.Context(), a, u.ID); !errors.Is(err, ErrConflict) || len(f.audits) != 3 {
		t.Fatal("repeat deactivation appended an effect", err)
	}
}
func TestMembershipCommandsValidateBeforeStorageAndDenyForeignAuthority(t *testing.T) {
	f := &membershipFixture{}
	s, a := membershipForTest(t, f)
	for _, in := range []CreateOrganizationInput{{}, {Name: " ", Slug: "x"}, {Name: "x", Slug: "x\x00"}, {Name: string([]byte{0xff}), Slug: "x"}, {Name: strings.Repeat("x", 65537), Slug: "x"}, {Name: "x", Slug: strings.Repeat("x", 2304)}} {
		if _, err := s.CreateOrganization(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
			t.Fatal("invalid organization reached storage")
		}
	}
	for _, in := range []CreateUserInput{{}, {Email: "person@example.test", DisplayName: " "}, {Email: "bad@@example.test", DisplayName: "x"}, {Email: "name <person@example.test>", DisplayName: "x"}, {Email: "person@example.test\r\nX: value", DisplayName: "x"}, {Email: "person@example.test", DisplayName: "x\x00"}, {Email: "person@example.test", DisplayName: string([]byte{0xff})}, {Email: "person@example.test", DisplayName: "x", OrganizationID: strings.Repeat("x", 1025)}} {
		if _, err := s.CreateUser(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
			t.Fatal("invalid user reached storage")
		}
	}
	for _, grants := range [][]identitydomain.ResourceGrant{nil, {{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"*"}}}, {{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}} {
		a.ResourceGrants = grants
		if _, err := s.CreateOrganization(t.Context(), a, CreateOrganizationInput{Name: "x", Slug: "x"}); !errors.Is(err, application.ErrForbidden) || f.calls != 0 {
			t.Fatal("resource-only membership administration accepted", err)
		}
	}
	a.KeyID, a.UserID = "key", ""
	f.orgs["foreign"] = identitydomain.Organization{ID: "foreign", TenantID: "other"}
	f.users["foreign"] = identitydomain.HumanUser{ID: "foreign", TenantID: "other", Status: "active"}
	if _, err := s.CreateUser(t.Context(), a, CreateUserInput{OrganizationID: "foreign", Email: "person@example.test", DisplayName: "Person"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign organization accepted", err)
	}
	if _, err := s.DeactivateUser(t.Context(), a, "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign user deactivated", err)
	}
	if len(f.audits) != 0 {
		t.Fatal("foreign membership attempt produced effects")
	}
}
func TestMembershipCommandsPublishNothingAfterInsertAuditOrCommitFailure(t *testing.T) {
	for _, operation := range []string{"organization", "user", "deactivate"} {
		for _, phase := range []string{"auth", "lock", "read", "write", "audit", "commit"} {
			f := &membershipFixture{phase: phase}
			s, a := membershipForTest(t, f)
			f.users["user"] = identitydomain.HumanUser{ID: "user", TenantID: a.TenantID, Email: "person@example.test", DisplayName: "Person", Status: "active", SchemaVersion: identitydomain.HumanUserSchemaVersion, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
			var err error
			switch operation {
			case "organization":
				_, err = s.CreateOrganization(t.Context(), a, CreateOrganizationInput{Name: "Example", Slug: "example"})
			case "user":
				_, err = s.CreateUser(t.Context(), a, CreateUserInput{Email: "other@example.test", DisplayName: "Other"})
			case "deactivate":
				_, err = s.DeactivateUser(t.Context(), a, "user")
			}
			if err == nil || len(f.orgs) != 0 || len(f.users) != 1 || f.users["user"].Status != "active" || len(f.audits) != 0 {
				t.Fatal("failed membership transaction published effects", operation, phase)
			}
		}
	}
}

func TestMembershipCommandsCancelBeforeStorageAndAfterStagedAudit(t *testing.T) {
	for _, late := range []bool{false, true} {
		f := &membershipFixture{}
		s, a := membershipForTest(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		if late {
			f.cancel = cancel
		} else {
			cancel()
		}
		out, err := s.CreateUser(ctx, a, CreateUserInput{Email: "person@example.test", DisplayName: "Person"})
		cancel()
		if !errors.Is(err, context.Canceled) || out.ID != "" || len(f.users) != 0 || len(f.audits) != 0 || !late && f.calls != 0 {
			t.Fatal("canceled command published effects", late, err)
		}
	}
}

func TestMembershipCommandsRejectMissingPortsInvalidClockAndIDs(t *testing.T) {
	f := &membershipFixture{}
	s, a := membershipForTest(t, f)
	for _, port := range []string{"transactions", "authorization", "clock", "ids"} {
		c := s.config
		switch port {
		case "transactions":
			c.Transactions = nil
		case "authorization":
			c.Authorizer = nil
		case "clock":
			c.Clock = nil
		case "ids":
			c.IDs = nil
		}
		if out, err := NewMembershipCommands(c); !errors.Is(err, ErrValidation) || out != nil {
			t.Fatal("missing membership dependency accepted", port, err)
		}
	}
	for _, invalid := range []string{"clock", "ids"} {
		f := &membershipFixture{}
		s, a := membershipForTest(t, f)
		if invalid == "clock" {
			s.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
		} else {
			s.config.IDs = application.IDGeneratorFunc(func(string) string { return "invalid\x00" })
		}
		if out, err := s.CreateOrganization(t.Context(), a, CreateOrganizationInput{Name: "Example", Slug: "example"}); !errors.Is(err, ErrValidation) || out.ID != "" || len(f.orgs)+len(f.audits) != 0 {
			t.Fatal("invalid identity/time published effects", invalid, err)
		}
	}
	for _, invalidContext := range []context.Context{nil} {
		if out, err := s.CreateUser(invalidContext, a, CreateUserInput{Email: "person@example.test", DisplayName: "Person"}); !errors.Is(err, ErrValidation) || out.ID != "" || f.calls != 0 {
			t.Fatal("nil request context reached storage", err)
		}
	}
}
