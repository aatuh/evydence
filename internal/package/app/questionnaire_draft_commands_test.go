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

var errDraftUnit = errors.New("private draft fault")

// The focused command cannot read payloads, prompts, arbitrary metadata or a
// whole answer library. Answer text is fetched only for an authorized winner.
type draftCommandFixture struct {
	scope                          QuestionnaireDraftScope
	questions                      []DraftQuestion
	candidates                     []DraftAnswerCandidate
	answer                         DraftAnswer
	evidence                       []string
	drafts                         []packagedomain.QuestionnaireDraft
	audits                         []application.AuditEvent
	phase                          string
	reads, textReads, transactions int
	cancel                         context.CancelFunc
}

func (f *draftCommandFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.TenantID == "" || a.KeyID == "" && a.UserID == "" {
		return application.ErrUnauthorized
	}
	if r.Scope != ScopePackageRead || !a.HasScope(r.Scope) || f.phase == "authorization" || f.phase == "root authorization" && !r.ScopeOnly {
		return application.ErrForbidden
	}
	if f.phase == "global answer denied" && !r.ScopeOnly && r.Resources == (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return nil
}
func (f *draftCommandFixture) ExecuteQuestionnaireDraft(ctx context.Context, _ string, fn func(context.Context, QuestionnaireDraftTransaction) error) error {
	f.transactions++
	d, a := len(f.drafts), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errDraftUnit
	}
	if err != nil {
		f.drafts = f.drafts[:d]
		f.audits = f.audits[:a]
	}
	return err
}
func (f *draftCommandFixture) ReadQuestionnaireDraftScope(_ context.Context, tenant string, in CreateQuestionnaireDraftInput) (QuestionnaireDraftScope, error) {
	f.reads++
	if f.phase == "scope" {
		return QuestionnaireDraftScope{}, errDraftUnit
	}
	if tenant != f.scope.TenantID && f.phase != "foreign scope" || in.TemplateID != f.scope.TemplateID {
		return QuestionnaireDraftScope{}, ErrNotFound
	}
	return f.scope, nil
}
func (f *draftCommandFixture) ReadQuestionnaireDraftQuestions(context.Context, QuestionnaireDraftScope) ([]DraftQuestion, error) {
	f.reads++
	if f.phase == "questions" {
		return nil, errDraftUnit
	}
	return append([]DraftQuestion(nil), f.questions...), nil
}
func (f *draftCommandFixture) ReadQuestionnaireDraftCandidates(context.Context, QuestionnaireDraftScope, DraftQuestion, int) ([]DraftAnswerCandidate, error) {
	f.reads++
	if f.phase == "candidates" {
		return nil, errDraftUnit
	}
	return append([]DraftAnswerCandidate(nil), f.candidates...), nil
}
func (f *draftCommandFixture) ReadQuestionnaireDraftAnswer(context.Context, QuestionnaireDraftScope, string) (DraftAnswer, error) {
	f.textReads++
	if f.phase == "answer" {
		return DraftAnswer{}, errDraftUnit
	}
	return f.answer, nil
}
func (f *draftCommandFixture) ReadQuestionnaireDraftEvidence(context.Context, QuestionnaireDraftScope, DraftQuestion, int) ([]string, error) {
	f.reads++
	if f.phase == "evidence" {
		return nil, errDraftUnit
	}
	return append([]string(nil), f.evidence...), nil
}
func (f *draftCommandFixture) ValidateQuestionnaireDraftEvidence(context.Context, QuestionnaireDraftScope, []string) error {
	if f.phase == "citation validation" {
		return ErrNotFound
	}
	return nil
}
func (f *draftCommandFixture) InsertQuestionnaireDraft(_ context.Context, v packagedomain.QuestionnaireDraft) error {
	if f.phase == "insert" {
		return errDraftUnit
	}
	f.drafts = append(f.drafts, v)
	return nil
}
func (f *draftCommandFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errDraftUnit
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func newDraftCommandFixture(t *testing.T) (*QuestionnaireDraftCommands, *draftCommandFixture, identitydomain.Actor, CreateQuestionnaireDraftInput) {
	t.Helper()
	refs := application.ResourceReferences{ProductID: "product", ReleaseID: "release"}
	f := &draftCommandFixture{scope: QuestionnaireDraftScope{TenantID: "tenant", TemplateID: "template", ProductID: "product", ReleaseID: "release", Resources: refs}, questions: []DraftQuestion{{ID: "q", ControlID: "control", EvidenceType: "sbom"}}, evidence: []string{"b", "a"}, answer: DraftAnswer{ID: "specific", TenantID: "tenant", Answer: "Reviewed draft", EvidenceIDs: []string{"b", "a"}, Limitations: []string{"Human review required"}}}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f.candidates = []DraftAnswerCandidate{{ID: "global", TenantID: "tenant", QuestionID: "q", CreatedAt: now.Add(time.Hour)}, {ID: "specific", TenantID: "tenant", QuestionID: "q", ControlID: "control", EvidenceType: "sbom", ProductID: "product", ReleaseID: "release", Resources: refs, CreatedAt: now}}
	n := 0
	c, err := NewQuestionnaireDraftCommands(QuestionnaireDraftCommandConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{ScopePackageRead}}, CreateQuestionnaireDraftInput{TemplateID: "template", ProductID: "product", ReleaseID: "release"}
}
func TestDraftCommandPreservesRankingHashShapeAndAtomicAudit(t *testing.T) {
	c, f, a, in := newDraftCommandFixture(t)
	v, err := c.CreateQuestionnaireDraft(t.Context(), a, in)
	if err != nil || len(v.Responses) != 1 || v.Responses[0].Answer != "Reviewed draft" || !reflect.DeepEqual(v.Responses[0].EvidenceIDs, []string{"b", "a"}) || v.SchemaVersion != packagedomain.QuestionnaireDraftVersion {
		t.Fatal("draft selection or order changed", v, err)
	}
	raw, err := EncodeQuestionnaireResponses(v.Responses)
	if err != nil {
		t.Fatal(err)
	}
	want, err := application.NormalizedJSONHash(json.RawMessage(raw))
	if err != nil || want != v.ManifestHash {
		t.Fatal("manifest hash changed", err)
	}
	if len(f.drafts) != 1 || len(f.audits) != 1 || f.audits[0].PayloadHash != v.ManifestHash || f.audits[0].ActorID != a.KeyID || f.audits[0].EntryType != "questionnaire_draft.created" {
		t.Fatal("draft/audit effects differ")
	}
	encoded, err := EncodeQuestionnaireDraft(v)
	if err != nil || !strings.Contains(string(encoded), `"manifest_hash"`) || strings.Contains(string(encoded), `"ManifestHash"`) {
		t.Fatal("document shape", err)
	}
	v.Responses[0].EvidenceIDs[0] = "mutated"
	v.Responses[0].Limitations[0] = "mutated"
	v.Limitations[0] = "mutated"
	if f.drafts[0].Responses[0].EvidenceIDs[0] != "b" || f.drafts[0].Responses[0].Limitations[0] == "mutated" || f.drafts[0].Limitations[0] == "mutated" {
		t.Fatal("returned draft mutates committed record")
	}
}
func TestDraftCommandFallbackAndDeniedAnswerNeverReadPrivateText(t *testing.T) {
	for _, variant := range []string{"no candidates", "global answer denied", "no evidence"} {
		t.Run(variant, func(t *testing.T) {
			c, f, a, in := newDraftCommandFixture(t)
			f.candidates = nil
			if variant == "global answer denied" {
				f.phase = variant
				f.candidates = []DraftAnswerCandidate{fCandidateGlobal()}
			}
			if variant == "no evidence" {
				f.evidence = nil
			}
			v, err := c.CreateQuestionnaireDraft(t.Context(), a, in)
			if err != nil || f.textReads != 0 || len(v.Responses) != 1 {
				t.Fatal("fallback read unauthorized answer", err)
			}
			r := v.Responses[0]
			want := "Evidence is available for review in the linked evidence records."
			if variant == "no evidence" {
				want = "No matching evidence is recorded for this question."
			}
			if r.Answer != want || len(r.Limitations) != 1 || variant != "no evidence" && !reflect.DeepEqual(r.EvidenceIDs, []string{"a", "b"}) {
				t.Fatal("fallback changed", r)
			}
		})
	}
}
func fCandidateGlobal() DraftAnswerCandidate {
	return DraftAnswerCandidate{ID: "global", TenantID: "tenant", QuestionID: "q", CreatedAt: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
}
func TestDraftCommandFailuresPublishNothing(t *testing.T) {
	for _, phase := range []string{"authorization", "root authorization", "scope", "questions", "candidates", "answer", "evidence", "citation validation", "insert", "audit", "commit", "cancel", "foreign scope", "foreign candidate", "foreign answer", "wrong answer", "empty questions", "duplicate questions", "too many questions", "too many candidates", "too many citations", "oversized answer", "oversized output"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := newDraftCommandFixture(t)
			f.phase = phase
			want := errDraftUnit
			ctx := t.Context()
			switch phase {
			case "authorization", "root authorization":
				want = application.ErrForbidden
			case "evidence":
				f.candidates = nil
			case "citation validation":
				want = ErrNotFound
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				f.cancel = cancel
				want = context.Canceled
			case "foreign scope":
				f.scope.TenantID = "other"
				want = ErrNotFound
			case "foreign candidate":
				f.candidates[0].TenantID = "other"
				want = ErrNotFound
			case "foreign answer":
				f.answer.TenantID = "other"
				want = ErrNotFound
			case "wrong answer":
				f.answer.ID = "other"
				want = ErrConflict
			case "empty questions":
				f.questions = nil
				want = ErrValidation
			case "duplicate questions":
				f.questions = append(f.questions, f.questions[0])
				want = ErrConflict
			case "too many questions":
				f.questions = make([]DraftQuestion, MaxQuestionnaireDraftQuestions+1)
				want = ErrValidation
			case "too many candidates":
				f.candidates = make([]DraftAnswerCandidate, MaxQuestionnaireDraftFacts+1)
				want = ErrValidation
			case "too many citations":
				f.answer.EvidenceIDs = make([]string, MaxQuestionnaireDraftFacts+1)
				want = ErrValidation
			case "oversized answer":
				f.answer.Answer = strings.Repeat("x", MaxQuestionnaireDraftAnswerBytes+1)
				want = ErrValidation
			case "oversized output":
				f.questions = make([]DraftQuestion, 100)
				for i := range f.questions {
					f.questions[i] = DraftQuestion{ID: fmt.Sprint(i), ControlID: "control", EvidenceType: "sbom"}
				}
				f.answer.Answer = strings.Repeat("x", 50000)
				want = ErrValidation
			}
			v, err := c.CreateQuestionnaireDraft(ctx, a, in)
			if !errors.Is(err, want) || v.ID != "" || len(f.drafts)+len(f.audits) != 0 {
				t.Fatalf("partial draft phase=%s err=%v want=%v writes=%d", phase, err, want, len(f.drafts)+len(f.audits))
			}
			if phase == "authorization" && f.reads != 0 || phase == "root authorization" && f.reads != 1 || phase == "foreign candidate" && f.textReads != 0 {
				t.Fatal("denial still read private data")
			}
		})
	}
}
func TestDraftCommandInputAndReplayGuardAreBoundedReadOnly(t *testing.T) {
	for _, variant := range []string{"blank", "long", "long padding", "nul", "utf8", "actor", "canceled"} {
		t.Run(variant, func(t *testing.T) {
			c, f, a, in := newDraftCommandFixture(t)
			want := ErrValidation
			ctx := t.Context()
			switch variant {
			case "blank":
				in.TemplateID = " "
			case "long":
				in.ReleaseID = strings.Repeat("x", 1025)
			case "long padding":
				in.TemplateID = strings.Repeat(" ", 1024) + "template"
			case "nul":
				in.ProductID = "product\x00"
			case "utf8":
				in.TemplateID = string([]byte{0xff})
			case "actor":
				a.KeyID = ""
				want = application.ErrUnauthorized
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			}
			if _, err := c.CreateQuestionnaireDraft(ctx, a, in); !errors.Is(err, want) || f.transactions != 0 {
				t.Fatal("invalid input reached draft transaction", err)
			}
		})
	}
	c, f, a, in := newDraftCommandFixture(t)
	if err := c.AuthorizeCreateQuestionnaireDraft(t.Context(), a, in); err != nil || f.reads != 1 || f.textReads != 0 || len(f.drafts)+len(f.audits) != 0 {
		t.Fatal("replay guard reads answers or writes", err)
	}
	f.phase = "root authorization"
	if err := c.AuthorizeCreateQuestionnaireDraft(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("replay bypasses grant", err)
	}
}

func TestDraftCommandCombinedCandidateMetadataHasOneBudget(t *testing.T) {
	c, f, a, in := newDraftCommandFixture(t)
	f.questions = []DraftQuestion{{ID: "q1", EvidenceType: "sbom"}, {ID: "q2", EvidenceType: "sbom"}}
	f.candidates = make([]DraftAnswerCandidate, 800)
	for i := range f.candidates {
		f.candidates[i] = DraftAnswerCandidate{ID: fmt.Sprintf("%04d", i) + strings.Repeat("i", 996), TenantID: a.TenantID, QuestionID: strings.Repeat("q", 1000), ControlID: strings.Repeat("c", 1000), EvidenceType: "sbom", ProductID: in.ProductID, ReleaseID: in.ReleaseID, Resources: f.scope.Resources, CreatedAt: time.Unix(1, 0)}
	}
	f.answer.ID = f.candidates[0].ID
	if v, err := c.CreateQuestionnaireDraft(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || len(f.drafts)+len(f.audits) != 0 {
		t.Fatal("combined candidate budget ignored", err)
	}
}

func TestDraftCommandCandidateCoordinatesCannotSubstituteGrants(t *testing.T) {
	c, f, a, in := newDraftCommandFixture(t)
	f.candidates[1].Resources.ProductID = "other"
	if v, err := c.CreateQuestionnaireDraft(t.Context(), a, in); !errors.Is(err, ErrConflict) || v.ID != "" || f.textReads != 0 {
		t.Fatal("incoherent candidate authorization", err)
	}
}

func TestDraftAnswerSelectionUsesRecencyThenStableID(t *testing.T) {
	_, f, a, _ := newDraftCommandFixture(t)
	x := f.candidates[1]
	y := x
	y.ID = "z"
	y.CreatedAt = x.CreatedAt.Add(time.Second)
	z := y
	z.ID = "a"
	winner, ok, err := selectDraftAnswer(t.Context(), f, a, f.scope, f.questions[0], []DraftAnswerCandidate{x, y, z})
	if err != nil || !ok || winner.ID != "a" {
		t.Fatal("unstable answer ranking", winner, err)
	}
}
