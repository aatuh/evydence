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

var errAnswerLibrary = errors.New("private answer storage fault")

type answerLibraryFixture struct {
	phase                string
	checks, transactions int
	entries              []packagedomain.QuestionnaireAnswerLibraryEntry
	audits               []application.AuditEvent
	cancel               context.CancelFunc
}

func (f *answerLibraryFixture) ExecuteAnswerLibrary(ctx context.Context, _ string, fn func(context.Context, AnswerLibraryTransaction) error) error {
	f.transactions++
	n, m := len(f.entries), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errAnswerLibrary
	}
	if err != nil {
		f.entries, f.audits = f.entries[:n], f.audits[:m]
	}
	return err
}
func (f *answerLibraryFixture) ReadAnswerLibraryScope(_ context.Context, tenant, product, release string) (AnswerLibraryScope, error) {
	s := AnswerLibraryScope{TenantID: tenant, ProductID: product, ReleaseID: release, Resources: application.ResourceReferences{ProductID: product, ReleaseID: release}}
	if release != "" {
		s.Resources.ProductID = "product"
	}
	if f.phase == "root" {
		return s, ErrNotFound
	}
	if f.phase == "forged-root" {
		s.TenantID = "foreign"
	}
	return s, nil
}
func (f *answerLibraryFixture) ValidateAnswerLibraryReferences(_ context.Context, _ AnswerLibraryScope, control string, ids []string) error {
	f.checks++
	if control != "control" || !reflect.DeepEqual(ids, []string{"a", "a", "b"}) {
		return ErrValidation
	}
	if f.phase == "references" {
		return ErrNotFound
	}
	return nil
}
func (f *answerLibraryFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopePackageWrite || !a.HasScope(r.Scope) {
		return application.ErrForbidden
	}
	if !r.ScopeOnly && a.UserID != "" && a.KeyID == "" && len(a.ResourceGrants) == 0 {
		return application.ErrForbidden
	}
	return ctx.Err()
}
func (f *answerLibraryFixture) InsertAnswerLibraryEntry(_ context.Context, v packagedomain.QuestionnaireAnswerLibraryEntry) error {
	if f.phase == "insert" {
		return errAnswerLibrary
	}
	f.entries = append(f.entries, v)
	return nil
}
func (f *answerLibraryFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errAnswerLibrary
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func newAnswerLibraryFixture(t *testing.T) (*AnswerLibraryCommands, *answerLibraryFixture, identitydomain.Actor, CreateAnswerLibraryEntryInput) {
	t.Helper()
	f := &answerLibraryFixture{}
	n := 0
	c, err := NewAnswerLibraryCommands(AnswerLibraryCommandConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 3, 12, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopePackageWrite}}, CreateAnswerLibraryEntryInput{QuestionID: " q ", ControlID: " control ", ReleaseID: " release ", Answer: " Draft answer ", EvidenceIDs: []string{" b ", "a", "a"}, Limitations: []string{" z ", "a", "a", " "}}
}
func TestAnswerLibraryCommandPreservesScopeShapeCopiesAndAtomicAudit(t *testing.T) {
	c, f, a, in := newAnswerLibraryFixture(t)
	v, err := c.CreateAnswerLibraryEntry(t.Context(), a, in)
	if err != nil || v.ProductID != "" || v.ReleaseID != "release" || v.QuestionID != "q" || v.Answer != "Draft answer" || !reflect.DeepEqual(v.EvidenceIDs, []string{"a", "a", "b"}) || !reflect.DeepEqual(v.Limitations, []string{"", "a", "a", "z"}) || v.CreatedAt.Nanosecond() != 123456000 {
		t.Fatal("legacy normalization/scope differs", v, err)
	}
	if len(f.entries) != 1 || len(f.audits) != 1 || f.audits[0].SubjectID != v.ID || f.audits[0].SubjectType != "questionnaire_answer_library" || f.audits[0].EntryType != "questionnaire_answer_library.created" || f.audits[0].ActorID != a.KeyID || f.audits[0].PayloadHash != "" || !f.audits[0].OccurredAt.Equal(v.CreatedAt) {
		t.Fatal("atomic audit differs")
	}
	raw, err := EncodeAnswerLibraryEntry(v)
	var doc map[string]any
	if err != nil || json.Unmarshal(raw, &doc) != nil || doc["answer"] != "Draft answer" || doc["product_id"] != nil || doc["evidence_type"] != nil || doc["Answer"] != nil {
		t.Fatal("public shape differs", string(raw), err)
	}
	v.EvidenceIDs[0] = "mutated"
	v.Limitations[0] = "mutated"
	in.EvidenceIDs[0] = "input mutation"
	if f.entries[0].EvidenceIDs[0] != "a" || f.entries[0].Limitations[0] != "" {
		t.Fatal("stored immutable slices alias caller")
	}
	in.Limitations = nil
	v, err = c.CreateAnswerLibraryEntry(t.Context(), a, in)
	if err == nil {
		t.Fatal("mutated citation fixture unexpectedly accepted", v)
	}
	in.EvidenceIDs = []string{"a", "a", "b"}
	v, err = c.CreateAnswerLibraryEntry(t.Context(), a, in)
	if err != nil || !reflect.DeepEqual(v.Limitations, []string{AnswerLibraryReviewLimitation}) {
		t.Fatal("default warning differs", v, err)
	}
}
func TestAnswerLibraryCommandFailuresAndReadOnlyReplayGuard(t *testing.T) {
	for _, phase := range []string{"root", "forged-root", "references", "insert", "audit", "commit", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := newAnswerLibraryFixture(t)
			f.phase = phase
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.cancel = cancel
			want := errAnswerLibrary
			if phase == "root" || phase == "forged-root" || phase == "references" {
				want = ErrNotFound
			}
			if phase == "cancel" {
				want = context.Canceled
			}
			v, err := c.CreateAnswerLibraryEntry(ctx, a, in)
			if !errors.Is(err, want) || v.ID != "" || len(f.entries)+len(f.audits) != 0 {
				t.Fatal("failed command published", v, err)
			}
		})
	}
	c, f, a, in := newAnswerLibraryFixture(t)
	if err := c.AuthorizeCreateAnswerLibraryEntry(t.Context(), a, in); err != nil || f.checks != 1 || len(f.entries)+len(f.audits) != 0 {
		t.Fatal("replay guard mutated or omitted references", err)
	}
	a.KeyID = ""
	a.UserID = "user"
	if err := c.AuthorizeCreateAnswerLibraryEntry(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.checks != 1 {
		t.Fatal("removed grants reached references/replay", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.CreateAnswerLibraryEntry(ctx, a, in); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := NewAnswerLibraryCommands(AnswerLibraryCommandConfig{}); !errors.Is(err, ErrValidation) {
		t.Fatal("missing dependencies accepted", err)
	}
}
func TestAnswerLibraryInputAndEncodedBudgets(t *testing.T) {
	for _, name := range []string{"answer", "selector", "id", "nul", "utf8", "citations", "blank-citation", "limitations", "text", "aggregate", "encoded"} {
		t.Run(name, func(t *testing.T) {
			c, f, a, in := newAnswerLibraryFixture(t)
			switch name {
			case "answer":
				in.Answer = " "
			case "selector":
				in.QuestionID = ""
				in.ControlID = ""
			case "id":
				in.ReleaseID = strings.Repeat(" ", MaxAnswerLibraryIDBytes+1)
			case "nul":
				in.Answer = "bad\x00text"
			case "utf8":
				in.EvidenceType = string([]byte{0xff})
			case "citations":
				in.EvidenceIDs = make([]string, MaxAnswerLibraryEvidenceIDs+1)
			case "blank-citation":
				in.EvidenceIDs = []string{" "}
			case "limitations":
				in.Limitations = make([]string, MaxAnswerLibraryLimitations+1)
			case "text":
				in.Answer = strings.Repeat("a", MaxAnswerLibraryTextBytes+1)
			case "aggregate":
				in.Limitations = make([]string, MaxAnswerLibraryLimitations)
				for i := range in.Limitations {
					in.Limitations[i] = strings.Repeat("a", MaxAnswerLibraryTextBytes)
				}
			case "encoded":
				in.Limitations = make([]string, 20)
				for i := range in.Limitations {
					in.Limitations[i] = strings.Repeat("<", MaxAnswerLibraryTextBytes)
				}
			}
			v, err := c.CreateAnswerLibraryEntry(t.Context(), a, in)
			if !errors.Is(err, ErrValidation) || v.ID != "" || len(f.entries)+len(f.audits) != 0 {
				t.Fatal("unbounded/invalid entry published", err)
			}
			if name != "encoded" && f.transactions != 0 {
				t.Fatal("invalid raw input reached transaction")
			}
		})
	}
	_, _, _, in := newAnswerLibraryFixture(t)
	in.Answer = strings.Repeat("a", MaxAnswerLibraryTextBytes)
	in.EvidenceIDs = make([]string, MaxAnswerLibraryEvidenceIDs)
	for i := range in.EvidenceIDs {
		in.EvidenceIDs[i] = "a"
	}
	in.Limitations = make([]string, MaxAnswerLibraryLimitations)
	if _, err := NormalizeAnswerLibraryInput(in); err != nil {
		t.Fatal("inclusive limits rejected", err)
	}
}
