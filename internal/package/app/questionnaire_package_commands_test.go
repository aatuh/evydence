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

func TestQuestionnaireResponseHashRejectsOverflowBeforeRecordCreation(t *testing.T) {
	values := []packagedomain.QuestionnaireResponse{{QuestionID: "q", Answer: "Reviewed", EvidenceIDs: []string{"a"}}}
	raw, err := EncodeQuestionnaireResponses(values)
	if err != nil {
		t.Fatal(err)
	}
	want, err := application.NormalizedJSONHash(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if hash, err := HashQuestionnaireResponses(values); err != nil || hash != want {
		t.Fatal("versioned hash changed", err)
	}
	for _, variant := range []string{"answer", "citations", "questions", "raw budget", "escaped budget"} {
		bad := append([]packagedomain.QuestionnaireResponse(nil), values...)
		switch variant {
		case "answer":
			bad[0].Answer = strings.Repeat("x", 65537)
		case "citations":
			bad[0].EvidenceIDs = make([]string, 4097)
		case "questions":
			bad = make([]packagedomain.QuestionnaireResponse, 513)
		case "raw budget", "escaped budget":
			bad = make([]packagedomain.QuestionnaireResponse, 80)
			text := "x"
			if variant == "escaped budget" {
				text = "\""
				bad = bad[:40]
			}
			for i := range bad {
				bad[i] = packagedomain.QuestionnaireResponse{QuestionID: fmt.Sprint(i), Answer: strings.Repeat(text, 65536)}
			}
		}
		if hash, err := HashQuestionnaireResponses(bad); !errors.Is(err, ErrValidation) || hash != "" {
			t.Fatal("unbounded response hash", variant, err)
		}
	}
}

type questionnairePackageFixture struct {
	*draftCommandFixture
	packageScope QuestionnairePackageScope
	packages     []packagedomain.QuestionnairePackage
	deniedScope  bool
}

func (f *questionnairePackageFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.TenantID == "" || a.KeyID == "" && a.UserID == "" {
		return application.ErrUnauthorized
	}
	if r.Scope != ScopePackageWrite || !a.HasScope(r.Scope) || f.phase == "authorization" || f.phase == "root authorization" && !r.ScopeOnly {
		return application.ErrForbidden
	}
	if !r.ScopeOnly && r.Resources == (application.ResourceReferences{}) && f.deniedScope {
		return application.ErrForbidden
	}
	return nil
}
func (f *questionnairePackageFixture) ReadQuestionnairePackageScope(_ context.Context, _ string, _ CreateQuestionnairePackageInput) (QuestionnairePackageScope, error) {
	f.reads++
	if f.phase == "scope" {
		return QuestionnairePackageScope{}, errDraftUnit
	}
	return f.packageScope, nil
}
func (f *questionnairePackageFixture) ExecuteQuestionnairePackage(ctx context.Context, _ string, fn func(context.Context, QuestionnairePackageTransaction) error) error {
	f.transactions++
	p, a := len(f.packages), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errDraftUnit
	}
	if err != nil {
		f.packages = f.packages[:p]
		f.audits = f.audits[:a]
	}
	return err
}
func (f *questionnairePackageFixture) InsertQuestionnairePackage(_ context.Context, v packagedomain.QuestionnairePackage) error {
	if f.phase == "insert" {
		return errDraftUnit
	}
	f.packages = append(f.packages, v)
	return nil
}
func newQuestionnairePackageFixture(t *testing.T) (*QuestionnairePackageCommands, *questionnairePackageFixture, identitydomain.Actor, CreateQuestionnairePackageInput) {
	t.Helper()
	_, d, a, in := newDraftCommandFixture(t)
	f := &questionnairePackageFixture{draftCommandFixture: d, packageScope: QuestionnairePackageScope{Selection: d.scope, PackageID: "package", PackageResources: application.ResourceReferences{ProductID: "product", ReleaseID: "release", CustomerPackageID: "package"}}}
	a.Scopes = []string{ScopePackageWrite}
	n := 0
	c, err := NewQuestionnairePackageCommands(QuestionnairePackageCommandConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, a, CreateQuestionnairePackageInput{TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, PackageID: "package"}
}
func TestQuestionnairePackageCommandPreservesScopeHashAuditAndIsolation(t *testing.T) {
	c, f, a, in := newQuestionnairePackageFixture(t)
	v, err := c.CreateQuestionnairePackage(t.Context(), a, in)
	if err != nil || v.PackageID != in.PackageID || v.ProductID != in.ProductID || v.ReleaseID != in.ReleaseID || v.SchemaVersion != packagedomain.QuestionnairePackageVersion || len(v.Responses) != 1 || v.Responses[0].Answer != "Reviewed draft" || !reflect.DeepEqual(v.Responses[0].EvidenceIDs, []string{"b", "a"}) {
		t.Fatal("package contract changed", v, err)
	}
	raw, err := EncodeQuestionnaireResponses(v.Responses)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := application.NormalizedJSONHash(json.RawMessage(raw))
	if err != nil || hash != v.ManifestHash || len(f.packages) != 1 || len(f.audits) != 1 || f.audits[0].PayloadHash != hash || f.audits[0].ActorID != a.KeyID || f.audits[0].EntryType != "questionnaire_package.generated" {
		t.Fatal("hash/audit not atomic", err)
	}
	encoded, err := EncodeQuestionnairePackage(v)
	if err != nil || !strings.Contains(string(encoded), `"package_id":"package"`) || strings.Contains(string(encoded), `"Responses"`) {
		t.Fatal("transport shape changed", err)
	}
	v.Responses[0].EvidenceIDs[0] = "mutated"
	v.Responses[0].Limitations[0] = "mutated"
	if f.packages[0].Responses[0].EvidenceIDs[0] != "b" || f.packages[0].Responses[0].Limitations[0] == "mutated" {
		t.Fatal("caller mutates committed package")
	}
}
func TestQuestionnairePackageCommandSeparatesSelectionAndAssociation(t *testing.T) {
	for _, variant := range []string{"global selection denied", "foreign template", "incoherent association", "unexpected association", "oversized resolved parent", "release only", "association does not filter"} {
		t.Run(variant, func(t *testing.T) {
			c, f, a, in := newQuestionnairePackageFixture(t)
			want := error(nil)
			switch variant {
			case "global selection denied", "association does not filter":
				in.ProductID, in.ReleaseID = "", ""
				f.packageScope.Selection.ProductID, f.packageScope.Selection.ReleaseID = "", ""
				f.packageScope.Selection.Resources = application.ResourceReferences{}
				f.candidates = nil
				if variant == "global selection denied" {
					f.deniedScope = true
					want = application.ErrForbidden
				}
			case "foreign template":
				f.packageScope.Selection.TenantID = "other"
				want = ErrNotFound
			case "incoherent association":
				f.packageScope.PackageResources.ProductID = "other"
				want = ErrConflict
			case "unexpected association":
				in.PackageID = ""
				want = ErrConflict
			case "oversized resolved parent":
				in.ProductID = ""
				f.packageScope.Selection.ProductID = ""
				f.packageScope.Selection.Resources.ProductID = strings.Repeat("p", 1025)
				f.packageScope.PackageResources.ProductID = f.packageScope.Selection.Resources.ProductID
				f.candidates = nil
				want = ErrConflict
			case "release only":
				in.ProductID = ""
				f.packageScope.Selection.ProductID = ""
				f.candidates = nil
			}
			v, err := c.CreateQuestionnairePackage(t.Context(), a, in)
			if !errors.Is(err, want) {
				t.Fatal("selection/association error", err, want)
			}
			if want != nil && (v.ID != "" || len(f.packages)+len(f.audits) != 0 || f.textReads != 0 || f.reads != 1) {
				t.Fatal("denial read private data or wrote state")
			}
			if want == nil && v.ProductID != in.ProductID {
				t.Fatal("association silently changed selection")
			}
		})
	}
}
func TestQuestionnairePackageCommandFailuresPublishNothing(t *testing.T) {
	for _, phase := range []string{"authorization", "root authorization", "scope", "questions", "candidates", "answer", "citation validation", "insert", "audit", "commit", "cancel", "oversized answer", "too many candidates"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := newQuestionnairePackageFixture(t)
			f.phase = phase
			want := errDraftUnit
			ctx := t.Context()
			switch phase {
			case "authorization", "root authorization":
				want = application.ErrForbidden
			case "citation validation":
				want = ErrNotFound
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				f.cancel = cancel
				want = context.Canceled
			case "oversized answer":
				f.answer.Answer = strings.Repeat("x", MaxQuestionnaireDraftAnswerBytes+1)
				want = ErrValidation
			case "too many candidates":
				f.candidates = make([]DraftAnswerCandidate, MaxQuestionnaireDraftFacts+1)
				want = ErrValidation
			}
			v, err := c.CreateQuestionnairePackage(ctx, a, in)
			if !errors.Is(err, want) || v.ID != "" || len(f.packages)+len(f.audits) != 0 {
				t.Fatal("partial package", phase, err)
			}
		})
	}
}
func TestQuestionnairePackageCommandReplayGuardReadsOnlyScope(t *testing.T) {
	c, f, a, in := newQuestionnairePackageFixture(t)
	if err := c.AuthorizeCreateQuestionnairePackage(t.Context(), a, in); err != nil || f.reads != 1 || f.textReads != 0 || len(f.packages)+len(f.audits) != 0 {
		t.Fatal("replay guard reads content or writes", err)
	}
	for _, bad := range []string{"", strings.Repeat(" ", 1024) + "template", "x\x00", string([]byte{0xff})} {
		in.TemplateID = bad
		before := f.transactions
		if _, err := c.CreateQuestionnairePackage(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != before {
			t.Fatal("invalid input reaches transaction", err)
		}
	}
}
