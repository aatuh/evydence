package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type templateGuardFixture struct {
	TemplateTransaction // Unsupported definition reads and writes panic.
	locks               []string
	denied              bool
}

func (f *templateGuardFixture) ExecuteReportTemplate(ctx context.Context, fn func(context.Context, TemplateTransaction) error) error {
	return fn(ctx, f)
}
func (f *templateGuardFixture) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.denied && r.TenantWide {
		return application.ErrForbidden
	}
	return nil
}
func (f *templateGuardFixture) LockReportTemplateTenant(context.Context, string) error {
	f.locks = append(f.locks, "tenant")
	return nil
}
func (f *templateGuardFixture) LockReportTemplateIdentity(_ context.Context, _ string, id string) error {
	f.locks = append(f.locks, "template:"+id)
	return nil
}

type panicTemplateHasher struct{}

func (panicTemplateHasher) HashReportOutput(context.Context, map[string]any) (string, error) {
	panic("guard hashed report")
}

func TestReportTemplateGuardsReadOnlyTenantAndTemplateIdentity(t *testing.T) {
	f := &templateGuardFixture{}
	s, err := NewTemplateCommands(TemplateCommandConfig{Transactions: f, Authorizer: f, Hasher: panicTemplateHasher{}, Clock: application.ClockFunc(func() time.Time { panic("guard used clock") }), IDs: application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })})
	if err != nil {
		t.Fatal(err)
	}
	create := CreateReportTemplateInput{Name: "Name", Version: "1", ReportType: "metadata", AllowedFields: []string{"subject_id", "subject_id", "unknown"}, Template: "{{ never execute }}"}
	render := RenderReportInput{TemplateID: " template ", SubjectType: " arbitrary label ", SubjectID: "nonexistent-resource-label"}
	if err := s.AuthorizeReportTemplateCreation(t.Context(), packageTestActor(), create); err != nil || !reflect.DeepEqual(f.locks, []string{"tenant"}) {
		t.Fatal("create guard read definition or did not lock tenant", err, f.locks)
	}
	f.locks = nil
	if err := s.AuthorizeReportRendering(t.Context(), packageTestActor(), render); err != nil || !reflect.DeepEqual(f.locks, []string{"tenant", "template:template"}) {
		t.Fatal("render guard inspected subject or definition", err, f.locks)
	}
	f.denied = true
	if err := s.AuthorizeReportRendering(t.Context(), packageTestActor(), render); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed authority retained replay", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.AuthorizeReportTemplateCreation(ctx, packageTestActor(), create); !errors.Is(err, context.Canceled) {
		t.Fatal("guard ignored cancellation", err)
	}
}
