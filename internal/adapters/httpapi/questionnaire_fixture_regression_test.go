package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type questionnaireFixtureScope struct {
	controlFixtureScope
	template domain.QuestionnaireTemplate
	entry    domain.QuestionnaireAnswerLibraryEntry
	pkg      domain.CustomerSecurityPackage
}

func seedQuestionnaireFixtureScope(t *testing.T, ledger *app.Ledger, name string) questionnaireFixtureScope {
	t.Helper()
	f := questionnaireFixtureScope{controlFixtureScope: seedControlFixtureScope(t, ledger, name)}
	var err error
	f.template, err = ledger.CreateQuestionnaireTemplate(t.Context(), f.actor, app.CreateQuestionnaireTemplateInput{Name: name, Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q1", Prompt: "Reviewed?", EvidenceType: "security_review", ControlID: f.control.ID, AllowedFields: []string{"title"}}}})
	if err != nil {
		t.Fatal(err)
	}
	f.entry, err = ledger.CreateQuestionnaireAnswerLibraryEntry(t.Context(), f.actor, app.CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: "q1", EvidenceType: "security_review", ControlID: f.control.ID, ProductID: f.product.ID, ReleaseID: f.release.ID, Answer: "Recorded scoped review", EvidenceIDs: []string{f.evidence.ID}, Limitations: []string{"Human review required"}})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ledger.CreateRedactionProfile(t.Context(), f.actor, app.CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil {
		t.Fatal(err)
	}
	f.pkg, err = ledger.CreateCustomerSecurityPackage(t.Context(), f.actor, app.CreateCustomerPackageInput{ProductID: f.product.ID, ReleaseID: f.release.ID, RedactionProfileID: profile.ID, Title: "Review", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func questionnaireFixtureHuman(f questionnaireFixtureScope) domain.Actor {
	return domain.Actor{TenantID: f.actor.TenantID, UserID: "fixture-human", Scopes: []string{"package:write", "package:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: f.actor.TenantID, Scopes: []string{"package:write", "package:read"}}}}
}
func questionnaireFixtureRequests(f questionnaireFixtureScope) []struct{ name, path, body, audit string } {
	return []struct{ name, path, body, audit string }{
		{"template", "/v1/questionnaire-templates", fmt.Sprintf(`{"name":" New ","version":" 2 ","questions":[{"id":"q1","prompt":"Reviewed?","evidence_type":"security_review","control_id":%q,"allowed_fields":["title"]}]}`, f.control.ID), "questionnaire_template.created"},
		{"answer", "/v1/questionnaire-answer-library", fmt.Sprintf(`{"question_id":"q1","evidence_type":"security_review","control_id":%q,"product_id":%q,"release_id":%q,"answer":"Recorded scoped review","evidence_ids":[%q],"limitations":["Human review required"]}`, f.control.ID, f.product.ID, f.release.ID, f.evidence.ID), "questionnaire_answer_library.created"},
		{"package", "/v1/questionnaire-packages", fmt.Sprintf(`{"template_id":%q,"package_id":%q,"product_id":%q,"release_id":%q}`, f.template.ID, f.pkg.ID, f.product.ID, f.release.ID), "questionnaire_package.generated"},
	}
}

type failingQuestionnaireFixture struct {
	questionnaireFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingQuestionnaireFixture) failure(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private questionnaire failure after write")
}
func (f *failingQuestionnaireFixture) CreateQuestionnaireTemplate(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnaireTemplateInput) (packagedomain.QuestionnaireTemplate, error) {
	v, err := f.questionnaireFixtureCommands.CreateQuestionnaireTemplate(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingQuestionnaireFixture) CreateAnswerLibraryEntry(ctx context.Context, a domain.Actor, in packageapp.CreateAnswerLibraryEntryInput) (packagedomain.QuestionnaireAnswerLibraryEntry, error) {
	v, err := f.questionnaireFixtureCommands.CreateAnswerLibraryEntry(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingQuestionnaireFixture) CreateQuestionnairePackage(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnairePackageInput) (packagedomain.QuestionnairePackage, error) {
	v, err := f.questionnaireFixtureCommands.CreateQuestionnairePackage(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func TestQuestionnaireFixturesRollBackAllRecordCitationAuditAndReplayEffects(t *testing.T) {
	for index := 0; index < 3; index++ {
		ledger, factory := integrationRegressionLedger()
		owner := seedQuestionnaireFixtureScope(t, ledger, "Owner")
		request := questionnaireFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			s, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			s.authn = &configuredAuthenticator{actor: questionnaireFixtureHuman(owner)}
			f := &failingQuestionnaireFixture{questionnaireFixtureCommands: questionnaireFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			s.questionnaireTemplateCommands, s.questionnairePackageCommands, s.answerLibraryCommands = f, f, f
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, s, "fixture-auth", request.path, "failed", []byte(request.body), 500)
			if f.changedID == "" || !f.isolated || strings.Contains(out, f.changedID) || strings.Contains(out, "private questionnaire") || strings.Contains(out, `"data"`) {
				t.Fatal("failed command bypassed real isolated write or exposed partial DTO", out)
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != 1 {
				t.Fatal("missing failure marker", err)
			}
			for _, r := range after.Idempotency {
				if r.State != app.IdempotencyFailed || r.Status != 0 || r.Response != nil {
					t.Fatal("failed questionnaire retained a success result")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed questionnaire committed template, answer, package, citations, audit or other effects")
			}
		})
	}
}
func TestQuestionnaireFixturesPreserveCompleteDTOHashAndPermissionBoundReplay(t *testing.T) {
	for index := 0; index < 3; index++ {
		ledger, factory := integrationRegressionLedger()
		owner, foreign := seedQuestionnaireFixtureScope(t, ledger, "Owner"), seedQuestionnaireFixtureScope(t, ledger, "Foreign")
		request := questionnaireFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			s, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			human := questionnaireFixtureHuman(owner)
			auth := &configuredAuthenticator{actor: human}
			s.authn = auth
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			first := postRaw(t, s, "fixture-auth", request.path, "same", []byte(request.body), 201)
			saved, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			id := dataField(t, first, "id")
			var v any
			hash := ""
			switch request.name {
			case "template":
				v = saved.QuestionnaireTemplates[id]
				if len(saved.QuestionnaireTemplates) != len(before.QuestionnaireTemplates)+1 || saved.QuestionnaireTemplates[id].Name != "New" || saved.QuestionnaireTemplates[id].Version != "2" {
					t.Fatal("template normalization or insert count changed")
				}
			case "answer":
				v = saved.AnswerLibrary[id]
				if len(saved.AnswerLibrary) != len(before.AnswerLibrary)+1 || !reflect.DeepEqual(saved.AnswerLibrary[id].EvidenceIDs, []string{owner.evidence.ID}) || !reflect.DeepEqual(saved.AnswerLibrary[id].Limitations, []string{"Human review required"}) {
					t.Fatal("answer lost citations/limitations")
				}
			case "package":
				p := saved.QuestionnairePackages[id]
				v = p
				hash = p.ManifestHash
				computed, err := packageapp.HashQuestionnaireResponses(questionnairePackageFixtureModel(p).Responses)
				if err != nil || computed != hash || len(saved.QuestionnairePackages) != len(before.QuestionnairePackages)+1 || p.TemplateID != owner.template.ID || p.PackageID != owner.pkg.ID || p.ProductID != owner.product.ID || p.ReleaseID != owner.release.ID || len(p.Responses) != 1 || p.Responses[0].Answer != owner.entry.Answer || !reflect.DeepEqual(p.Responses[0].EvidenceIDs, owner.entry.EvidenceIDs) {
					t.Fatal("package changed scope, ranked answer, citations or canonical hash", err)
				}
			}
			want, err := json.Marshal(map[string]any{"data": v, "meta": map[string]string{"api_version": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, string(want), first)
			if len(saved.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || len(saved.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("questionnaire lost atomic audit/replay")
			}
			last := saved.AuditEntries[human.TenantID][len(saved.AuditEntries[human.TenantID])-1]
			if last.EntryType != request.audit || last.ActorType != "human_user" || last.ActorID != human.UserID || last.SubjectID != id || last.PayloadHash != hash {
				t.Fatal("questionnaire audit lost actor, subject or hash binding")
			}
			assertTrustHTTPReplay(t, first, postRaw(t, s, "fixture-auth", request.path, "same", []byte(request.body), 201))
			if request.name == "package" {
				// Permission sets are canonicalized, but an actual change must
				// conflict even when the actor can still access the selected root.
				auth.actor.Scopes = []string{"package:read", "package:write", "package:write"}
				assertTrustHTTPReplay(t, first, postRaw(t, s, "fixture-auth", request.path, "same", []byte(request.body), 201))
				auth.actor.Scopes = append(auth.actor.Scopes, "evidence:read")
				postRaw(t, s, "fixture-auth", request.path, "same", []byte(request.body), 409)
			}
			auth.actor = human
			postRaw(t, s, "fixture-auth", request.path, "same", append([]byte(request.body), ' '), 409)
			auth.actor.ResourceGrants = nil
			postRaw(t, s, "fixture-auth", request.path, "same", []byte(request.body), 403)
			postRaw(t, s, "fixture-auth", request.path, "denied-fresh", []byte(request.body), 403)
			auth.actor = human
			foreignIDs := map[string]string{owner.control.ID: foreign.control.ID, owner.evidence.ID: foreign.evidence.ID, owner.product.ID: foreign.product.ID, owner.release.ID: foreign.release.ID, owner.template.ID: foreign.template.ID, owner.pkg.ID: foreign.pkg.ID}
			for local, wrong := range foreignIDs {
				if strings.Contains(request.body, local) {
					postRaw(t, s, "fixture-auth", request.path, "foreign-"+local, []byte(strings.ReplaceAll(request.body, local, wrong)), 404)
				}
			}
			auth.err = app.ErrUnauthorized
			postRaw(t, s, "fixture-auth", request.path, "same", []byte(request.body), 401)
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(saved, after) {
				t.Fatal("replay, conflicts, revoked grants or foreign roots changed state", err)
			}
		})
	}
}
func TestQuestionnaireFixtureLibraryPagesAreScopedCompleteDetachedAndReadOnly(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedQuestionnaireFixtureScope(t, ledger, "Owner"), seedQuestionnaireFixtureScope(t, ledger, "Foreign")
	for _, f := range []questionnaireFixtureScope{owner, foreign} {
		for i := 0; i < 2; i++ {
			if _, err := ledger.CreateQuestionnaireAnswerLibraryEntry(t.Context(), f.actor, app.CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: "q1", ProductID: f.product.ID, ReleaseID: f.release.ID, Answer: "Another scoped answer", EvidenceIDs: []string{f.evidence.ID}, Limitations: []string{"Review"}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := ledger.CreateQuestionnaireAnswerLibraryEntry(t.Context(), owner.actor, app.CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: "q1", Answer: "private-global-answer"}); err != nil {
		t.Fatal(err)
	}
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := questionnaireFixtureHuman(owner)
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: human.Scopes}}
	auth := &configuredAuthenticator{actor: human}
	s.authn = auth
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	path := "/v1/questionnaire-answer-library?question_id=q1&page_size=1"
	for {
		out := getJSON(t, s, "fixture-auth", path, 200)
		var page struct {
			Data []domain.QuestionnaireAnswerLibraryEntry `json:"data"`
			Meta struct {
				NextCursor string `json:"next_cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal([]byte(out), &page); err != nil || len(page.Data) != 1 || page.Data[0].TenantID != owner.actor.TenantID || seen[page.Data[0].ID] || strings.Contains(out, "private-global-answer") || !reflect.DeepEqual(page.Data[0], before.AnswerLibrary[page.Data[0].ID]) {
			t.Fatal("answer page lost fields, leaked text or repeated data", err)
		}
		seen[page.Data[0].ID] = true
		if page.Meta.NextCursor == "" {
			break
		}
		path = "/v1/questionnaire-answer-library?question_id=q1&page_size=1&cursor=" + url.QueryEscape(page.Meta.NextCursor)
	}
	if len(seen) != 3 {
		t.Fatal("answer pages truncated scoped records")
	}
	getJSON(t, s, "fixture-auth", "/v1/questionnaire-answer-library?product_id="+foreign.product.ID, 404)
	q := answerLibraryFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	page, err := q.ListPage(t.Context(), human, packagequery.AnswerLibraryFilter{}, appquery.PageRequest{PageSize: 10, Sort: appquery.SortID, Direction: appquery.Ascending}, nil)
	if err != nil || len(page.Items) != 3 {
		t.Fatal("fixture page missing answers", err)
	}
	page.Items[0].EvidenceIDs[0], page.Items[0].Limitations[0] = "changed", "changed"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := q.ListPage(ctx, human, packagequery.AnswerLibraryFilter{}, appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("answer reader ignored cancellation", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("answer reads shared slices or wrote state", err)
	}
}
func TestQuestionnaireFixtureMappersPreserveAllFieldsAndDetachNestedMetadata(t *testing.T) {
	at := time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)
	template := domain.QuestionnaireTemplate{ID: "template", TenantID: "tenant", Name: "Name", Version: "2", Questions: []domain.QuestionnaireQuestion{{ID: "q", Prompt: "Prompt", EvidenceType: "review", ControlID: "control", AllowedFields: []string{"title"}}}, SchemaVersion: "schema", CreatedAt: at}
	pkg := domain.QuestionnairePackage{ID: "package", TenantID: "tenant", TemplateID: "template", PackageID: "customer", ProductID: "product", ReleaseID: "release", Responses: []domain.QuestionnaireResponse{{QuestionID: "q", Answer: "Answer", EvidenceIDs: []string{"evidence"}, Limitations: []string{"Review"}}}, ManifestHash: "sha256:hash", SchemaVersion: "schema", CreatedAt: at}
	entry := domain.QuestionnaireAnswerLibraryEntry{ID: "entry", TenantID: "tenant", QuestionID: "q", EvidenceType: "review", ControlID: "control", ProductID: "product", ReleaseID: "release", Answer: "Answer", EvidenceIDs: []string{"evidence"}, Limitations: []string{"Review"}, SchemaVersion: "schema", CreatedAt: at}
	tm, pm, am := questionnaireTemplateFixtureModel(template), questionnairePackageFixtureModel(pkg), answerLibraryFixtureModel(entry)
	for _, pair := range []struct{ legacy, encoded any }{{template, map[string]any{"id": tm.ID, "tenant_id": tm.TenantID, "name": tm.Name, "version": tm.Version, "questions": questionnaireQuestionsFromCommand(tm.Questions), "schema_version": tm.SchemaVersion, "created_at": tm.CreatedAt}}, {pkg, domain.QuestionnairePackage{ID: pm.ID, TenantID: pm.TenantID, TemplateID: pm.TemplateID, PackageID: pm.PackageID, ProductID: pm.ProductID, ReleaseID: pm.ReleaseID, Responses: []domain.QuestionnaireResponse{{QuestionID: pm.Responses[0].QuestionID, Answer: pm.Responses[0].Answer, EvidenceIDs: pm.Responses[0].EvidenceIDs, Limitations: pm.Responses[0].Limitations}}, ManifestHash: pm.ManifestHash, SchemaVersion: pm.SchemaVersion, CreatedAt: pm.CreatedAt}}, {entry, answerLibraryEntryFromQuery(am)}} {
		a, err := json.Marshal(pair.legacy)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(pair.encoded)
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(a), string(b))
	}
	tm.Questions[0].AllowedFields[0] = "changed"
	pm.Responses[0].EvidenceIDs[0] = "changed"
	pm.Responses[0].Limitations[0] = "changed"
	am.EvidenceIDs[0] = "changed"
	am.Limitations[0] = "changed"
	if !slices.Equal(template.Questions[0].AllowedFields, []string{"title"}) || pkg.Responses[0].EvidenceIDs[0] != "evidence" || pkg.Responses[0].Limitations[0] != "Review" || entry.EvidenceIDs[0] != "evidence" || entry.Limitations[0] != "Review" {
		t.Fatal("questionnaire mapping shared nested metadata")
	}
}

func TestQuestionnaireFixtureGuardsArePureCancellableAndPreserveExplicitPorts(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedQuestionnaireFixtureScope(t, ledger, "Owner")
	f := questionnaireFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	requests := questionnaireFixtureRequests(owner)
	template, err := decodeQuestionnaireTemplateRequest([]byte(requests[0].body))
	if err != nil {
		t.Fatal(err)
	}
	answer, err := decodeAnswerLibraryRequest([]byte(requests[1].body))
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := decodeQuestionnairePackageRequest([]byte(requests[2].body))
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []func(context.Context) error{
		func(ctx context.Context) error {
			return f.AuthorizeCreateQuestionnaireTemplate(ctx, questionnaireFixtureHuman(owner), template)
		},
		func(ctx context.Context) error {
			return f.AuthorizeCreateAnswerLibraryEntry(ctx, questionnaireFixtureHuman(owner), answer)
		},
		func(ctx context.Context) error {
			return f.AuthorizeCreateQuestionnairePackage(ctx, questionnaireFixtureHuman(owner), pkg)
		},
	} {
		if err := guard(t.Context()); err != nil {
			t.Fatal("owned questionnaire guard failed", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := guard(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("questionnaire guard ignored cancellation", err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("questionnaire preflight wrote state", err)
	}
	templates, packages, answers := &qTemplateHTTPFake{}, &questionnairePackageHTTPFake{}, &answerLibraryHTTPFake{}
	query := &struct{ AnswerLibraryQuery }{}
	s, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{QuestionnaireTemplateCommands: templates, QuestionnairePackageCommands: packages, AnswerLibraryCommands: answers, AnswerLibraryQuery: query, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	s.bindLegacyLedgerFixture(newLegacyLedgerFixture(app.Config{}))
	if s.questionnaireTemplateCommands != templates || s.questionnairePackageCommands != packages || s.answerLibraryCommands != answers || s.answerLibraryQuery != query {
		t.Fatal("binder replaced explicit questionnaire ports")
	}
}
