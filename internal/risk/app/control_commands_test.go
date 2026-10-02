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
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type controlCommandFixture struct {
	frameworkExists, versionExists, codeExists    bool
	authError, readError, insertError, auditError error
	transactions, authorizations, reads           int
	authFailAt                                    int
	frameworks                                    []riskdomain.ControlFramework
	controls                                      []riskdomain.SecurityControl
	audits                                        []application.AuditEvent
}

func (f *controlCommandFixture) ExecuteControls(ctx context.Context, command func(context.Context, ControlTransaction) error) error {
	f.transactions++
	beforeF, beforeC, beforeA := len(f.frameworks), len(f.controls), len(f.audits)
	if err := command(ctx, f); err != nil {
		f.frameworks, f.controls, f.audits = f.frameworks[:beforeF], f.controls[:beforeC], f.audits[:beforeA]
		return err
	}
	return nil
}
func (f *controlCommandFixture) Authorize(_ context.Context, _ identitydomain.Actor, request application.AuthorizationRequest) error {
	f.authorizations++
	if f.authFailAt != 0 && f.authorizations == f.authFailAt {
		return application.ErrForbidden
	}
	if request.Scope != "controls:admin" || !request.TenantWide || request.ScopeOnly || request.Resources != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return f.authError
}
func (f *controlCommandFixture) FrameworkVersionExists(context.Context, string, string, string) (bool, error) {
	f.reads++
	return f.versionExists, f.readError
}
func (f *controlCommandFixture) ControlFrameworkExists(context.Context, string, string) (bool, error) {
	f.reads++
	return f.frameworkExists, f.readError
}
func (f *controlCommandFixture) SecurityControlCodeExists(context.Context, string, string, string) (bool, error) {
	f.reads++
	return f.codeExists, f.readError
}
func (f *controlCommandFixture) InsertControlFramework(_ context.Context, v riskdomain.ControlFramework) error {
	f.frameworks = append(f.frameworks, v)
	return f.insertError
}
func (f *controlCommandFixture) InsertSecurityControl(_ context.Context, v riskdomain.SecurityControl) error {
	f.controls = append(f.controls, v)
	return f.insertError
}
func (f *controlCommandFixture) AppendAudit(_ context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	f.audits = append(f.audits, event)
	return application.AuditReceipt{ID: event.ID}, f.auditError
}

func newControlCommandFixture(t *testing.T) (*ControlCommands, *controlCommandFixture, identitydomain.Actor, time.Time) {
	t.Helper()
	f := &controlCommandFixture{frameworkExists: true}
	now := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	s, err := NewControlCommands(ControlCommandConfig{Authorizer: f, Transactions: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "-id" })})
	if err != nil {
		t.Fatal(err)
	}
	return s, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"controls:admin"}}, now
}

func TestControlCommandsPreserveFieldsAndNormalizeWithoutCallerMutation(t *testing.T) {
	s, f, actor, now := newControlCommandFixture(t)
	fw, err := s.CreateControlFramework(t.Context(), actor, CreateControlFrameworkInput{Name: " SSDF / Core ", Version: " 1 ", Description: " Description "})
	wantF := riskdomain.ControlFramework{ID: "fw-id", TenantID: "tenant", Name: "SSDF / Core", Slug: "ssdf-core", Version: "1", Description: "Description", Status: "active", SchemaVersion: riskdomain.ControlFrameworkSchemaVersion, CreatedAt: now}
	if err != nil || !reflect.DeepEqual(fw, wantF) || !reflect.DeepEqual(f.frameworks, []riskdomain.ControlFramework{wantF}) {
		t.Fatal("framework fields changed", fw, err)
	}
	in := CreateSecurityControlInput{FrameworkID: " fw-id ", Code: " C-1 ", Title: " Title ", Objective: " Objective ", EvidenceRequirements: []riskdomain.ControlEvidenceRequirement{{Type: " sbom ", FreshnessDays: 3650, Required: true}, {Type: "build"}}, Applicability: []string{" z ", "", " a ", "a"}, Limitations: []string{" second ", " ", " first ", "first"}}
	control, err := s.CreateSecurityControl(t.Context(), actor, in)
	wantC := riskdomain.SecurityControl{ID: "ctrl-id", TenantID: "tenant", FrameworkID: "fw-id", Code: "C-1", Title: "Title", Objective: "Objective", EvidenceRequirements: []riskdomain.ControlEvidenceRequirement{{Type: "sbom", FreshnessDays: 3650, Required: true}, {Type: "build"}}, Applicability: []string{"", "a", "a", "z"}, Limitations: []string{"second", "first", "first"}, SchemaVersion: riskdomain.SecurityControlSchemaVersion, CreatedAt: now}
	if err != nil || !reflect.DeepEqual(control, wantC) || !reflect.DeepEqual(f.controls, []riskdomain.SecurityControl{wantC}) {
		t.Fatal("control fields changed", control, err)
	}
	if in.EvidenceRequirements[0].Type != " sbom " || in.Applicability[0] != " z " || in.Limitations[0] != " second " {
		t.Fatal("caller input mutated", in)
	}
	control.EvidenceRequirements[0].Type = "vex"
	control.Applicability[0] = "mutated"
	if f.controls[0].EvidenceRequirements[0].Type != "sbom" || f.controls[0].Applicability[0] != "" {
		t.Fatal("returned slices alias persisted values")
	}
	if f.transactions != 2 || f.authorizations != 4 || f.reads != 3 || len(f.audits) != 2 {
		t.Fatal("commands did not use focused atomic ports", f)
	}
	for i, typ := range []string{"control_framework", "security_control"} {
		a := f.audits[i]
		if a.TenantID != actor.TenantID || a.ActorID != "key" || a.ActorType != "api_key" || a.SubjectType != typ || a.EntryType != typ+".created" || a.OccurredAt != now || a.SubjectID == "" || a.ID == "" {
			t.Fatal("audit changed", a)
		}
	}
}

func TestControlCommandsFailClosedAndRollback(t *testing.T) {
	injected := errors.New("private storage failure")
	for _, test := range []struct {
		name   string
		change func(*controlCommandFixture)
		want   error
	}{
		{"removed grant", func(f *controlCommandFixture) { f.authError = application.ErrForbidden }, application.ErrForbidden},
		{"read failure", func(f *controlCommandFixture) { f.readError = injected }, injected},
		{"insert failure", func(f *controlCommandFixture) { f.insertError = injected }, injected},
		{"audit failure", func(f *controlCommandFixture) { f.auditError = injected }, injected},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, f, actor, _ := newControlCommandFixture(t)
			test.change(f)
			fw, err := s.CreateControlFramework(t.Context(), actor, CreateControlFrameworkInput{Name: "Framework", Version: "1"})
			if !errors.Is(err, test.want) || fw != (riskdomain.ControlFramework{}) {
				t.Fatal("framework error exposed result", fw, err)
			}
			c, err := s.CreateSecurityControl(t.Context(), actor, CreateSecurityControlInput{FrameworkID: "fw", Code: "C", Title: "Title", Objective: "Objective"})
			if !errors.Is(err, test.want) || c.ID != "" || len(f.frameworks)+len(f.controls)+len(f.audits) != 0 {
				t.Fatal("control failure published effects", c, f, err)
			}
		})
	}
	for _, test := range []struct {
		name                     string
		framework, version, code bool
		want                     error
	}{
		{"foreign or missing framework", false, false, false, ErrNotFound},
		{"duplicate framework version", true, true, false, ErrConflict},
		{"duplicate control code", true, false, true, ErrConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, f, actor, _ := newControlCommandFixture(t)
			f.frameworkExists, f.versionExists, f.codeExists = test.framework, test.version, test.code
			var err error
			if test.version {
				_, err = s.CreateControlFramework(t.Context(), actor, CreateControlFrameworkInput{Name: "F", Version: "1"})
			} else {
				_, err = s.CreateSecurityControl(t.Context(), actor, CreateSecurityControlInput{FrameworkID: "fw", Code: "C", Title: "T", Objective: "O"})
			}
			if !errors.Is(err, test.want) || len(f.frameworks)+len(f.controls)+len(f.audits) != 0 {
				t.Fatal("invalid coordinates wrote records", f, err)
			}
		})
	}
}

func TestControlCommandsRejectInvalidAndExcessiveInputBeforeTransactions(t *testing.T) {
	for _, bad := range []CreateControlFrameworkInput{
		{}, {Name: "中文", Version: "1"}, {Name: "N", Version: " "}, {Name: "N\x00", Version: "1"}, {Name: string([]byte{0xff}), Version: "1"},
		{Name: strings.Repeat("x", 65537), Version: "1"}, {Name: "N", Slug: strings.Repeat("x", 1024), Version: "1"},
	} {
		s, f, actor, _ := newControlCommandFixture(t)
		if _, err := s.CreateControlFramework(t.Context(), actor, bad); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal("bad framework crossed transaction boundary", err, f.transactions)
		}
	}
	base := CreateSecurityControlInput{FrameworkID: "fw", Code: "C", Title: "T", Objective: "O"}
	for _, change := range []func(*CreateSecurityControlInput){
		func(v *CreateSecurityControlInput) { v.FrameworkID = "" }, func(v *CreateSecurityControlInput) { v.Code = strings.Repeat("c", 1025) },
		func(v *CreateSecurityControlInput) { v.Objective = "x\x00" }, func(v *CreateSecurityControlInput) { v.Title = string([]byte{0xff}) },
		func(v *CreateSecurityControlInput) {
			v.EvidenceRequirements = []riskdomain.ControlEvidenceRequirement{{Type: "other"}}
		},
		func(v *CreateSecurityControlInput) {
			v.EvidenceRequirements = []riskdomain.ControlEvidenceRequirement{{Type: "sbom"}, {Type: " sbom "}}
		},
		func(v *CreateSecurityControlInput) {
			v.EvidenceRequirements = []riskdomain.ControlEvidenceRequirement{{Type: "sbom", FreshnessDays: -1}}
		},
		func(v *CreateSecurityControlInput) {
			v.EvidenceRequirements = []riskdomain.ControlEvidenceRequirement{{Type: "sbom", FreshnessDays: 3651}}
		},
		func(v *CreateSecurityControlInput) { v.Applicability = make([]string, 1025) },
		func(v *CreateSecurityControlInput) { v.Limitations = []string{strings.Repeat("x", 65537)} },
		func(v *CreateSecurityControlInput) {
			v.Applicability = []string{strings.Repeat("x", 65536)}
			v.Limitations = []string{"x"}
		},
	} {
		s, f, actor, _ := newControlCommandFixture(t)
		bad := base
		change(&bad)
		if _, err := s.CreateSecurityControl(t.Context(), actor, bad); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal("bad control crossed transaction boundary", err, f.transactions)
		}
	}
}

func TestControlCommandsRecheckAuthorizationBeforeTransactionReads(t *testing.T) {
	s, f, actor, _ := newControlCommandFixture(t)
	f.authFailAt = 2
	if _, err := s.CreateControlFramework(t.Context(), actor, CreateControlFrameworkInput{Name: "F", Version: "1"}); !errors.Is(err, application.ErrForbidden) || f.transactions != 1 || f.reads != 0 || len(f.frameworks)+len(f.audits) != 0 {
		t.Fatal("transaction grant denial read or wrote state", f, err)
	}
	s, f, actor, _ = newControlCommandFixture(t)
	f.authFailAt = 2
	if _, err := s.CreateSecurityControl(t.Context(), actor, CreateSecurityControlInput{FrameworkID: "fw", Code: "C", Title: "T", Objective: "O"}); !errors.Is(err, application.ErrForbidden) || f.transactions != 1 || f.reads != 0 || len(f.controls)+len(f.audits) != 0 {
		t.Fatal("control grant denial read or wrote state", f, err)
	}
}

func TestControlCommandsAcceptExactInputBudgets(t *testing.T) {
	s, _, actor, _ := newControlCommandFixture(t)
	if _, err := s.CreateControlFramework(t.Context(), actor, CreateControlFrameworkInput{Name: strings.Repeat("n", 65536), Slug: strings.Repeat("s", 1023), Version: "1", Description: strings.Repeat("d", 65536)}); err != nil {
		t.Fatal("exact framework budgets rejected", err)
	}
	for _, in := range []CreateSecurityControlInput{
		{FrameworkID: "fw", Code: strings.Repeat("c", 1024), Title: strings.Repeat("t", 65536), Objective: strings.Repeat("o", 65536), Applicability: make([]string, 1024)},
		{FrameworkID: "fw", Code: "C", Title: "T", Objective: "O", Applicability: []string{strings.Repeat("a", 32768)}, Limitations: []string{strings.Repeat("l", 32768)}},
	} {
		if _, err := s.CreateSecurityControl(t.Context(), actor, in); err != nil {
			t.Fatal("exact control budgets rejected", err)
		}
	}
}

func TestControlAdminAuthorizerEnforcesTenantGrantAndRequestShape(t *testing.T) {
	policy := NewControlAdminAuthorizer()
	for _, tc := range []struct {
		name  string
		actor identitydomain.Actor
		want  error
	}{
		{"anonymous", identitydomain.Actor{}, application.ErrUnauthorized},
		{"key", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopeControlsAdmin}}, nil},
		{"collector", identitydomain.Actor{TenantID: "tenant", CollectorID: "collector", Scopes: []string{ScopeControlsAdmin}}, nil},
		{"key without scope", identitydomain.Actor{TenantID: "tenant", KeyID: "key"}, application.ErrForbidden},
		{"human without grant", identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{ScopeControlsAdmin}}, application.ErrForbidden},
		{"tenant human", identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{ScopeControlsAdmin}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{ScopeControlsAdmin}}}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := policy.Authorize(t.Context(), tc.actor, controlAdminRequest()); !errors.Is(err, tc.want) {
				t.Fatal("tenant policy changed", err, tc.want)
			}
		})
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin"}}
	for _, bad := range []application.AuthorizationRequest{{Scope: ScopeControlsAdmin, ScopeOnly: true}, {Scope: "admin", TenantWide: true}, {Scope: ScopeControlsAdmin, TenantWide: true, Resources: application.ResourceReferences{ProductID: "product"}}} {
		if err := policy.Authorize(t.Context(), actor, bad); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("broad/mismatched authorization accepted", bad, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := policy.Authorize(ctx, actor, controlAdminRequest()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
}
