package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var errQTemplate = errors.New("private template storage fault")

type qTemplateFixture struct {
	phase                string
	controls             []string
	templates            []packagedomain.QuestionnaireTemplate
	audits               []application.AuditEvent
	transactions, checks int
	cancel               context.CancelFunc
}

func (f *qTemplateFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopePackageWrite || !r.TenantWide || r.Resources != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return application.AuthorizeTenantWideScope(ctx, a, r.Scope)
}

func (f *qTemplateFixture) ExecuteQuestionnaireTemplate(ctx context.Context, _ string, fn func(context.Context, QuestionnaireTemplateTransaction) error) error {
	f.transactions++
	n, a := len(f.templates), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errQTemplate
	}
	if err != nil {
		f.templates, f.audits = f.templates[:n], f.audits[:a]
	}
	return err
}
func (f *qTemplateFixture) ValidateQuestionnaireTemplateScope(_ context.Context, tenant string, ids []string) error {
	f.checks++
	f.controls = append([]string(nil), ids...)
	if tenant != "tenant" || f.phase == "scope" {
		return ErrNotFound
	}
	return nil
}
func (f *qTemplateFixture) InsertQuestionnaireTemplate(_ context.Context, v packagedomain.QuestionnaireTemplate) error {
	if f.phase == "insert" {
		return errQTemplate
	}
	f.templates = append(f.templates, v)
	return nil
}
func (f *qTemplateFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errQTemplate
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func newQTemplateFixture(t *testing.T) (*QuestionnaireTemplateCommands, *qTemplateFixture, identitydomain.Actor, CreateQuestionnaireTemplateInput) {
	t.Helper()
	f := &qTemplateFixture{}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	n := 0
	c, err := NewQuestionnaireTemplateCommands(QuestionnaireTemplateCommandConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	in := CreateQuestionnaireTemplateInput{Name: " Customer ", Version: " 1 ", Questions: []packagedomain.QuestionnaireQuestion{
		{ID: " b ", Prompt: " Review? ", ControlID: " z ", EvidenceType: " sbom ", AllowedFields: []string{" z ", "a", "a", " "}},
		{ID: "a", Prompt: "Build?", ControlID: "a"}, {ID: "c", Prompt: "Other?", ControlID: "z"},
	}}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopePackageWrite}}, in
}
func TestQTemplateCommandPreservesShapeOrderAndAtomicAudit(t *testing.T) {
	c, f, a, in := newQTemplateFixture(t)
	v, err := c.CreateQuestionnaireTemplate(t.Context(), a, in)
	if err != nil || v.Name != "Customer" || v.Version != "1" || v.Questions[0].ID != "b" || v.Questions[0].ControlID != "z" || v.Questions[0].Prompt != "Review?" || v.Questions[0].EvidenceType != "sbom" || !reflect.DeepEqual(v.Questions[0].AllowedFields, []string{"", "a", "a", "z"}) || !reflect.DeepEqual(f.controls, []string{"a", "z"}) {
		t.Fatal("normalization/selection changed", v, err)
	}
	if len(f.templates) != 1 || len(f.audits) != 1 || f.audits[0].EntryType != "questionnaire_template.created" || f.audits[0].SubjectType != "questionnaire_template" || f.audits[0].SubjectID != v.ID || f.audits[0].ActorID != a.KeyID || f.audits[0].PayloadHash != "" || !f.audits[0].OccurredAt.Equal(v.CreatedAt) {
		t.Fatal("atomic audit differs")
	}
	raw, err := EncodeQuestionnaireTemplate(v)
	var doc map[string]any
	if err != nil || json.Unmarshal(raw, &doc) != nil || len(doc) != 7 {
		t.Fatal("public shape", err, string(raw))
	}
	qs := doc["questions"].([]any)
	if len(qs[1].(map[string]any)) != 3 {
		t.Fatal("optional fields no longer omitted", qs[1])
	}
	v.Questions[0].AllowedFields[0] = "mutated"
	v.Questions[1].ID = "mutated"
	in.Questions[0].AllowedFields[0] = "input mutation"
	if f.templates[0].Questions[0].AllowedFields[0] != "" || f.templates[0].Questions[1].ID != "a" {
		t.Fatal("mutable aliases reach durable record")
	}
}
func TestQTemplateCommandFailuresAndReplayGuardPublishNothing(t *testing.T) {
	for _, phase := range []string{"scope", "insert", "audit", "commit", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := newQTemplateFixture(t)
			f.phase = phase
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.cancel = cancel
			want := errQTemplate
			if phase == "scope" {
				want = ErrNotFound
			}
			if phase == "cancel" {
				want = context.Canceled
			}
			v, err := c.CreateQuestionnaireTemplate(ctx, a, in)
			if !errors.Is(err, want) || v.ID != "" || len(f.templates)+len(f.audits) != 0 {
				t.Fatal("failed transaction published template", v, err)
			}
		})
	}
	c, f, a, in := newQTemplateFixture(t)
	if err := c.AuthorizeCreateQuestionnaireTemplate(t.Context(), a, in); err != nil || f.checks != 1 || len(f.templates)+len(f.audits) != 0 {
		t.Fatal("replay guard mutated", err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "p", Scopes: []string{ScopePackageWrite}}}
	if _, err := c.CreateQuestionnaireTemplate(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.transactions != 1 {
		t.Fatal("tenant-wide grant missing", err)
	}
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{ScopePackageWrite}}}
	if _, err := c.CreateQuestionnaireTemplate(t.Context(), a, in); err != nil {
		t.Fatal("tenant writer denied", err)
	}
	a.ResourceGrants = nil
	if err := c.AuthorizeCreateQuestionnaireTemplate(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grants replayed", err)
	}
}
func TestQTemplateNormalizationAndRecordBounds(t *testing.T) {
	for _, kind := range []string{"name", "version", "empty", "duplicate", "questions", "prompt", "utf8", "nul", "fields", "field", "budget", "raw whitespace"} {
		t.Run(kind, func(t *testing.T) {
			c, f, a, in := newQTemplateFixture(t)
			switch kind {
			case "name":
				in.Name = " "
			case "version":
				in.Version = strings.Repeat("x", 1025)
			case "empty":
				in.Questions = nil
			case "duplicate":
				in.Questions[1].ID = " b "
			case "questions":
				in.Questions = make([]packagedomain.QuestionnaireQuestion, 513)
			case "prompt":
				in.Questions[0].Prompt = strings.Repeat("x", 65537)
			case "utf8":
				in.Questions[0].ID = string([]byte{0xff})
			case "nul":
				in.Questions[0].ControlID = "a\x00"
			case "fields":
				in.Questions[0].AllowedFields = make([]string, 129)
			case "field":
				in.Questions[0].AllowedFields = []string{strings.Repeat("x", 1025)}
			case "raw whitespace":
				in.Questions[0].ID = strings.Repeat(" ", 1024) + "q"
			case "budget":
				in.Questions = make([]packagedomain.QuestionnaireQuestion, 65)
				for i := range in.Questions {
					in.Questions[i] = packagedomain.QuestionnaireQuestion{ID: fmt.Sprint(i), Prompt: strings.Repeat("x", 65536)}
				}
			}
			if _, err := c.CreateQuestionnaireTemplate(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
				t.Fatal("unsafe input reached transaction", err)
			}
		})
	}
	c, _, a, in := newQTemplateFixture(t)
	v, err := c.CreateQuestionnaireTemplate(t.Context(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"id", "tenant", "schema", "time", "canonical", "encoded"} {
		t.Run(kind, func(t *testing.T) {
			bad := cloneQuestionnaireTemplate(v)
			switch kind {
			case "id":
				bad.ID = ""
			case "tenant":
				bad.TenantID = "x\x00"
			case "schema":
				bad.SchemaVersion = "unknown"
			case "time":
				bad.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			case "canonical":
				bad.Questions[0].ID = " b "
			case "encoded":
				bad.Questions = make([]packagedomain.QuestionnaireQuestion, 50)
				for i := range bad.Questions {
					bad.Questions[i] = packagedomain.QuestionnaireQuestion{ID: fmt.Sprint(i), Prompt: strings.Repeat("<", 65536)}
				}
			}
			if err := ValidateQuestionnaireTemplateRecord(bad); !errors.Is(err, ErrValidation) {
				t.Fatal("invalid durable record accepted", err)
			}
		})
	}
	if _, err := NewQuestionnaireTemplateCommands(QuestionnaireTemplateCommandConfig{}); !errors.Is(err, ErrValidation) {
		t.Fatal("incomplete config accepted", err)
	}
}

func TestQTemplateAcceptsExactCollectionAndTextLimits(t *testing.T) {
	c, _, a, in := newQTemplateFixture(t)
	in.Name = strings.Repeat("n", MaxQuestionnaireTemplateTextBytes)
	in.Questions = make([]packagedomain.QuestionnaireQuestion, MaxQuestionnaireTemplateQuestions)
	for i := range in.Questions {
		in.Questions[i] = packagedomain.QuestionnaireQuestion{ID: fmt.Sprint(i), Prompt: "Review?"}
	}
	in.Questions[0].Prompt = strings.Repeat("p", MaxQuestionnaireTemplatePromptBytes)
	in.Questions[0].AllowedFields = make([]string, MaxQuestionnaireTemplateFields)
	for i := range in.Questions[0].AllowedFields {
		in.Questions[0].AllowedFields[i] = strings.Repeat("f", MaxQuestionnaireTemplateTextBytes)
	}
	v, err := c.CreateQuestionnaireTemplate(t.Context(), a, in)
	if err != nil || len(v.Questions) != MaxQuestionnaireTemplateQuestions || len(v.Questions[0].AllowedFields) != MaxQuestionnaireTemplateFields || len(v.Questions[0].Prompt) != MaxQuestionnaireTemplatePromptBytes {
		t.Fatal("valid limit boundary rejected", err)
	}
}
