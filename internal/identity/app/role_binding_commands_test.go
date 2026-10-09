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

type roleBindingFixture struct {
	bindings                        []identitydomain.RoleBinding
	audits                          []application.AuditEvent
	phase                           string
	calls                           int
	subject, resource               CreateRoleBindingInput
	foreignSubject, foreignResource bool
	cancel                          context.CancelFunc
}

func (f *roleBindingFixture) ExecuteRoleBinding(ctx context.Context, fn func(context.Context, RoleBindingTransaction) error) error {
	f.calls++
	staged := &roleBindingFixture{phase: f.phase, foreignSubject: f.foreignSubject, foreignResource: f.foreignResource, cancel: f.cancel}
	if err := fn(ctx, staged); err != nil {
		return err
	}
	if f.phase == "commit" {
		return errors.New("private role commit")
	}
	f.bindings = append(f.bindings, staged.bindings...)
	f.audits = append(f.audits, staged.audits...)
	f.subject, f.resource = staged.subject, staged.resource
	return nil
}
func (f *roleBindingFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.phase == "auth" {
		return application.ErrForbidden
	}
	return NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *roleBindingFixture) LockRoleBindingWrites(context.Context, string) error {
	if f.phase == "lock" {
		return errors.New("private role lock")
	}
	return nil
}
func (f *roleBindingFixture) ValidateSubject(_ context.Context, tenant, kind, id string) error {
	f.subject = CreateRoleBindingInput{SubjectType: kind, SubjectID: id}
	if f.foreignSubject {
		return ErrNotFound
	}
	if f.phase == "subject" {
		return errors.New("private role subject")
	}
	return nil
}
func (f *roleBindingFixture) ValidateResource(_ context.Context, tenant, kind, id string) error {
	f.resource = CreateRoleBindingInput{ResourceType: kind, ResourceID: id}
	if f.foreignResource {
		return ErrNotFound
	}
	if f.phase == "resource" {
		return errors.New("private role resource")
	}
	return nil
}
func (f *roleBindingFixture) InsertRoleBinding(_ context.Context, v identitydomain.RoleBinding) error {
	if f.phase == "write" {
		return errors.New("private role write")
	}
	f.bindings = append(f.bindings, v)
	return nil
}
func (f *roleBindingFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errors.New("private role audit")
	}
	f.audits = append(f.audits, v)
	if f.cancel != nil {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func roleBindingForTest(t *testing.T, f *roleBindingFixture) (*RoleBindingCommands, identitydomain.Actor) {
	t.Helper()
	s, err := NewRoleBindingCommands(RoleBindingCommandConfig{Transactions: f, Authorizer: NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 9, 1, 1, 2, 3, 123456789, time.FixedZone("fixture", 3600)) }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	return s, identitydomain.Actor{TenantID: "tenant", UserID: "operator", Scopes: []string{"identity:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"identity:admin"}}}}
}
func TestRoleBindingCommandsPreserveKnownRolesResourcesAndRepeatedAssignments(t *testing.T) {
	for _, role := range []string{"tenant_admin", "security_engineer", "release_manager", "customer_verifier", "collector"} {
		for _, kind := range []string{"", "tenant", "product", "project", "release", "customer_security_package", "evidence_bundle"} {
			for _, subject := range []string{"user", "collector"} {
				f := &roleBindingFixture{}
				s, a := roleBindingForTest(t, f)
				id := "resource"
				if kind == "" {
					id = ""
				}
				if kind == "tenant" {
					id = a.TenantID
				}
				in := CreateRoleBindingInput{SubjectType: " " + subject + " ", SubjectID: " subject ", Role: " " + role + " ", ResourceType: " " + kind + " ", ResourceID: " " + id + " "}
				v, err := s.CreateRoleBinding(t.Context(), a, in)
				if err != nil || v.SubjectType != subject || v.SubjectID != "subject" || v.Role != role || v.ResourceType != kind || v.ResourceID != id || v.TenantID != a.TenantID || v.SchemaVersion != identitydomain.RoleBindingSchemaVersion || v.CreatedAt.Location() != time.UTC || v.CreatedAt.Nanosecond()%1000 != 0 || len(f.audits) != 1 {
					t.Fatal("role binding contract changed", role, kind, subject, err)
				}
				if f.audits[0].EntryType != "role_binding.created" || f.audits[0].SubjectID != v.ID || f.audits[0].ActorType != "human_user" || f.audits[0].ActorID != a.UserID || f.subject.SubjectID != v.SubjectID || f.resource.ResourceID != v.ResourceID {
					t.Fatal("role binding parent/audit attribution lost")
				}
				if err := s.AuthorizeCreateRoleBinding(t.Context(), a, in); err != nil || len(f.bindings) != 1 || len(f.audits) != 1 {
					t.Fatal("role binding replay guard emitted effects", err)
				}
				if _, err := s.CreateRoleBinding(t.Context(), a, in); err != nil || len(f.bindings) != 2 || len(f.audits) != 2 {
					t.Fatal("repeated assignment compatibility changed", err)
				}
			}
		}
	}
}
func TestRoleBindingCommandsRejectBadInputsBeforeStorageAndDenyScopedAuthority(t *testing.T) {
	f := &roleBindingFixture{}
	s, a := roleBindingForTest(t, f)
	base := CreateRoleBindingInput{SubjectType: "user", SubjectID: "user", Role: "security_engineer"}
	for _, in := range []CreateRoleBindingInput{{}, {SubjectType: "group", SubjectID: "user", Role: "security_engineer"}, {SubjectType: "user", SubjectID: "user", Role: "instance:admin"}, {SubjectType: "user", SubjectID: "user", Role: "unknown"}, {SubjectType: "user", SubjectID: "user", Role: "security_engineer", ResourceID: "orphan"}, {SubjectType: "user", SubjectID: "user", Role: "security_engineer", ResourceType: "unknown"}, {SubjectType: "user", SubjectID: "bad\x00", Role: "security_engineer"}, {SubjectType: "user", SubjectID: string([]byte{0xff}), Role: "security_engineer"}, {SubjectType: "user", SubjectID: strings.Repeat("x", 1025), Role: "security_engineer"}} {
		if _, err := s.CreateRoleBinding(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
			t.Fatal("invalid role input reached storage", err)
		}
	}
	for _, kind := range []string{"product", "project", "release", "customer_security_package", "evidence_bundle"} {
		in := base
		in.ResourceType = kind
		if _, err := s.CreateRoleBinding(t.Context(), a, in); !errors.Is(err, ErrNotFound) || f.calls != 0 {
			t.Fatal("empty scoped target became tenant-wide", kind, err)
		}
	}
	for _, grants := range [][]identitydomain.ResourceGrant{nil, {{ResourceType: "tenant", ResourceID: "other", Scopes: []string{"*"}}}, {{ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}}} {
		a.ResourceGrants = grants
		if _, err := s.CreateRoleBinding(t.Context(), a, base); !errors.Is(err, application.ErrForbidden) || f.calls != 0 {
			t.Fatal("scoped human authority delegated tenant roles", err)
		}
	}
	a.KeyID, a.UserID = "key", ""
	for _, foreign := range []string{"subject", "resource"} {
		f.foreignSubject, f.foreignResource = foreign == "subject", foreign == "resource"
		if _, err := s.CreateRoleBinding(t.Context(), a, base); !errors.Is(err, ErrNotFound) || len(f.bindings)+len(f.audits) != 0 {
			t.Fatal("foreign grant target accepted", foreign, err)
		}
	}
}
func TestRoleBindingCommandsReturnNoEffectsAfterFailuresAndCancellation(t *testing.T) {
	for _, phase := range []string{"auth", "lock", "subject", "resource", "write", "audit", "commit", "cancel"} {
		f := &roleBindingFixture{phase: phase}
		s, a := roleBindingForTest(t, f)
		ctx, cancel := context.WithCancel(t.Context())
		if phase == "cancel" {
			f.cancel = cancel
		}
		out, err := s.CreateRoleBinding(ctx, a, CreateRoleBindingInput{SubjectType: "collector", SubjectID: "subject", Role: "collector", ResourceType: "tenant"})
		cancel()
		if err == nil || !reflect.DeepEqual(out, identitydomain.RoleBinding{}) || len(f.bindings)+len(f.audits) != 0 {
			t.Fatal("failed role binding published effects", phase, err)
		}
	}
	f := &roleBindingFixture{}
	s, a := roleBindingForTest(t, f)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.CreateRoleBinding(ctx, a, CreateRoleBindingInput{}); !errors.Is(err, context.Canceled) || f.calls != 0 {
		t.Fatal("canceled role request reached storage", err)
	}
}

func TestRoleBindingCommandsValidateEveryTextFieldAndDependencyOutput(t *testing.T) {
	base := CreateRoleBindingInput{SubjectType: "user", SubjectID: "user", Role: "collector", ResourceType: "product", ResourceID: "product"}
	for _, field := range []struct {
		name string
		max  int
		set  func(*CreateRoleBindingInput, string)
	}{
		{"subject_type", 128, func(in *CreateRoleBindingInput, v string) { in.SubjectType = v }},
		{"subject_id", 1024, func(in *CreateRoleBindingInput, v string) { in.SubjectID = v }},
		{"role", 128, func(in *CreateRoleBindingInput, v string) { in.Role = v }},
		{"resource_type", 128, func(in *CreateRoleBindingInput, v string) { in.ResourceType = v }},
		{"resource_id", 1024, func(in *CreateRoleBindingInput, v string) { in.ResourceID = v }},
	} {
		for _, bad := range []string{"bad\x00", string([]byte{0xff}), strings.Repeat("x", field.max+1)} {
			f := &roleBindingFixture{}
			s, a := roleBindingForTest(t, f)
			in := base
			field.set(&in, bad)
			if _, err := s.CreateRoleBinding(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.calls != 0 {
				t.Fatal("unsafe role text reached storage", field.name, err)
			}
		}
	}
	f := &roleBindingFixture{}
	s, a := roleBindingForTest(t, f)
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
		if command, err := NewRoleBindingCommands(config); !errors.Is(err, ErrValidation) || command != nil {
			t.Fatal("missing role dependency accepted", missing, err)
		}
	}
	//nolint:staticcheck // Intentionally prove nil-context rejection before storage.
	if _, err := s.CreateRoleBinding(nil, a, base); !errors.Is(err, ErrValidation) || f.calls != 0 {
		t.Fatal("nil role context reached storage", err)
	}
	var absent *RoleBindingCommands
	if _, err := absent.CreateRoleBinding(t.Context(), a, base); !errors.Is(err, ErrValidation) {
		t.Fatal("nil role command accepted", err)
	}
	for _, now := range []time.Time{{}, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		f := &roleBindingFixture{}
		s, a := roleBindingForTest(t, f)
		s.config.Clock = application.ClockFunc(func() time.Time { return now })
		if out, err := s.CreateRoleBinding(t.Context(), a, base); !errors.Is(err, ErrValidation) || out != (identitydomain.RoleBinding{}) || len(f.bindings)+len(f.audits) != 0 {
			t.Fatal("invalid role clock published effects", err)
		}
	}
	for _, prefix := range []string{"rbac", "ace"} {
		for _, bad := range []string{"", " padded ", "bad\x00", string([]byte{0xff}), strings.Repeat("x", 1025)} {
			f := &roleBindingFixture{}
			s, a := roleBindingForTest(t, f)
			s.config.IDs = application.IDGeneratorFunc(func(p string) string {
				if p == prefix {
					return bad
				}
				return p + "_valid"
			})
			if out, err := s.CreateRoleBinding(t.Context(), a, base); !errors.Is(err, ErrValidation) || out != (identitydomain.RoleBinding{}) || len(f.bindings)+len(f.audits) != 0 {
				t.Fatal("invalid generated role identity published effects", prefix, err)
			}
		}
	}
}
