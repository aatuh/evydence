package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type templateCommandFixture struct{ *controlCommandFixture }

func (f templateCommandFixture) ExecuteControlTemplate(ctx context.Context, command func(context.Context, ControlTemplateTransaction) error) error {
	return f.ExecuteControls(ctx, func(ctx context.Context, tx ControlTransaction) error {
		return command(ctx, tx.(ControlTemplateTransaction))
	})
}

func TestControlTemplateCommandsPreserveEveryStarterPackAndSingleAudit(t *testing.T) {
	for _, pack := range riskdomain.BuiltinTemplatePacks() {
		t.Run(pack.Slug, func(t *testing.T) {
			_, f, actor, now := newControlCommandFixture(t)
			ids := 0
			commands, err := NewControlTemplateCommands(ControlTemplateCommandConfig{Authorizer: f, Transactions: templateCommandFixture{f}, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { ids++; return fmt.Sprintf("%s-%d", prefix, ids) })})
			if err != nil {
				t.Fatal(err)
			}
			fw, err := commands.InstallControlFrameworkTemplatePack(t.Context(), actor, " "+pack.Slug+" ")
			want := riskdomain.ControlFramework{ID: "cf-1", TenantID: actor.TenantID, Name: pack.Name, Slug: pack.Slug, Version: pack.Version, Description: pack.Description, Status: "active", SchemaVersion: riskdomain.ControlFrameworkSchemaVersion, CreatedAt: now}
			if err != nil || !reflect.DeepEqual(fw, want) || !reflect.DeepEqual(f.frameworks, []riskdomain.ControlFramework{want}) || len(f.controls) != len(pack.Controls) || len(f.audits) != 1 || f.transactions != 1 || f.reads != 1 || f.authorizations != 2 {
				t.Fatal("template installation changed atomic effects", fw, f, err)
			}
			for i, template := range pack.Controls {
				want := template
				want.ID = fmt.Sprintf("ctrl-%d", i+2)
				want.TenantID = actor.TenantID
				want.FrameworkID = fw.ID
				want.SchemaVersion = riskdomain.SecurityControlSchemaVersion
				want.CreatedAt = now
				if !reflect.DeepEqual(f.controls[i], want) {
					t.Fatal("starter control changed", f.controls[i], want)
				}
			}
			a := f.audits[0]
			if a.EntryType != "control_framework_template.installed" || a.SubjectType != "control_framework" || a.SubjectID != fw.ID || a.TenantID != actor.TenantID || a.ActorType != "api_key" || a.ActorID != actor.KeyID || a.OccurredAt != now {
				t.Fatal("template audit changed", a)
			}
			pack.Controls[0].EvidenceRequirements[0].Type = "mutated"
			if f.controls[0].EvidenceRequirements[0].Type == "mutated" {
				t.Fatal("starter catalog aliases installed state")
			}
		})
	}
}

func TestControlTemplateCommandsFailClosedAndDoNotPublishPartialResults(t *testing.T) {
	injected := errors.New("private template storage failure")
	for _, tc := range []struct {
		name   string
		change func(*controlCommandFixture)
		want   error
	}{
		{"grant denied", func(f *controlCommandFixture) { f.authError = application.ErrForbidden }, application.ErrForbidden},
		{"grant removed inside transaction", func(f *controlCommandFixture) { f.authFailAt = 2 }, application.ErrForbidden},
		{"duplicate version", func(f *controlCommandFixture) { f.versionExists = true }, ErrConflict},
		{"read failed", func(f *controlCommandFixture) { f.readError = injected }, injected},
		{"insert failed", func(f *controlCommandFixture) { f.insertError = injected }, injected},
		{"audit failed", func(f *controlCommandFixture) { f.auditError = injected }, injected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, f, actor, now := newControlCommandFixture(t)
			tc.change(f)
			commands, err := NewControlTemplateCommands(ControlTemplateCommandConfig{Authorizer: f, Transactions: templateCommandFixture{f}, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "-id" })})
			if err != nil {
				t.Fatal(err)
			}
			v, err := commands.InstallControlFrameworkTemplatePack(t.Context(), actor, riskdomain.BuiltinTemplatePacks()[0].Slug)
			if !errors.Is(err, tc.want) || v != (riskdomain.ControlFramework{}) || len(f.frameworks)+len(f.controls)+len(f.audits) != 0 {
				t.Fatal("failed installation published", v, f, err)
			}
			if tc.name == "grant removed inside transaction" && f.reads != 0 {
				t.Fatal("read before transaction authorization")
			}
		})
	}
}

func TestControlTemplateCommandsBoundIdentifiersAndRejectUnknownPacks(t *testing.T) {
	_, f, actor, now := newControlCommandFixture(t)
	commands, err := NewControlTemplateCommands(ControlTemplateCommandConfig{Authorizer: f, Transactions: templateCommandFixture{f}, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "-id" })})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		slug string
		want error
	}{{"", ErrNotFound}, {"unknown", ErrNotFound}, {strings.Repeat("x", 1025), ErrValidation}, {"bad\x00slug", ErrValidation}, {string([]byte{0xff}), ErrValidation}} {
		if v, err := commands.InstallControlFrameworkTemplatePack(t.Context(), actor, tc.slug); !errors.Is(err, tc.want) || v.ID != "" || f.transactions != 0 {
			t.Fatal("invalid slug crossed transaction", tc.slug, v, err)
		}
	}
}

func TestControlTemplateCommandsBoundRawSlugBeforeTrim(t *testing.T) {
	_, f, a, now := newControlCommandFixture(t)
	c, err := NewControlTemplateCommands(ControlTemplateCommandConfig{Authorizer: f, Transactions: templateCommandFixture{f}, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "-id" })})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := c.InstallControlFrameworkTemplatePack(t.Context(), a, strings.Repeat(" ", 1025)+riskdomain.BuiltinTemplatePacks()[0].Slug); !errors.Is(err, ErrValidation) || v.ID != "" || f.transactions != 0 {
		t.Fatal("raw slug bypassed budget", err, f.transactions)
	}
}

func TestControlTemplateCommandsHaveReadOnlyReplayGuard(t *testing.T) {
	_, f, _, now := newControlCommandFixture(t)
	c, err := NewControlTemplateCommands(ControlTemplateCommandConfig{Authorizer: f, Transactions: templateCommandFixture{f}, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "-id" })})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(c).(interface {
		AuthorizeControlTemplateInstallation(context.Context, identitydomain.Actor, string) error
	}); !ok {
		t.Fatal("template installation has no current-tenant replay guard")
	}
}

func TestControlTemplateReplayGuardUsesOnlyCurrentTenantAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*controlCommandFixture)
		want   error
		locks  int
	}{
		{"installed metadata unavailable", func(f *controlCommandFixture) {
			f.versionExists = true
			f.readError = errors.New("private inventory failure")
		}, nil, 1},
		{"revoked inside transaction", func(f *controlCommandFixture) { f.authFailAt = 2 }, application.ErrForbidden, 0},
		{"tenant removed", func(f *controlCommandFixture) { f.tenantError = ErrNotFound }, ErrNotFound, 1},
		{"tenant storage unavailable", func(f *controlCommandFixture) { f.tenantError = errors.New("private tenant failure") }, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, f, a, _ := newControlCommandFixture(t)
			tc.change(f)
			want := tc.want
			if tc.name == "tenant storage unavailable" {
				want = f.tenantError
			}
			c, err := NewControlTemplateCommands(ControlTemplateCommandConfig{Authorizer: f, Transactions: templateCommandFixture{f}, Clock: application.ClockFunc(func() time.Time { panic("replay read clock") }), IDs: application.IDGeneratorFunc(func(string) string { panic("replay generated ID") })})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.AuthorizeControlTemplateInstallation(t.Context(), a, riskdomain.BuiltinTemplatePacks()[0].Slug); !errors.Is(err, want) || f.reads != 0 || f.tenantLocks != tc.locks || f.transactions != 1 || f.authorizations != 2 || len(f.frameworks)+len(f.controls)+len(f.audits) != 0 {
				t.Fatal("replay consulted installed state or changed effects", err, f)
			}
		})
	}
}
