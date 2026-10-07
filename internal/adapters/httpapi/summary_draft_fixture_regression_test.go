package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type failingSummaryDraftFixture struct {
	summaryDraftFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingSummaryDraftFixture) fail(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private summary draft failure after write")
}
func (f *failingSummaryDraftFixture) CreateEvidenceSummary(ctx context.Context, a domain.Actor, in packageapp.CreateEvidenceSummaryInput) (packagedomain.EvidenceSummary, error) {
	v, err := f.summaryDraftFixtureCommands.CreateEvidenceSummary(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingSummaryDraftFixture) CreateQuestionnaireDraft(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnaireDraftInput) (packagedomain.QuestionnaireDraft, error) {
	v, err := f.summaryDraftFixtureCommands.CreateQuestionnaireDraft(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func summaryDraftFixtureRequests(f questionnaireFixtureScope) []struct{ name, path, body, audit string } {
	return []struct{ name, path, body, audit string }{
		{"summary", "/v1/evidence-summaries", fmt.Sprintf(`{"subject_type":"release","subject_id":%q,"evidence_ids":[%q]}`, f.release.ID, f.evidence.ID), "evidence_summary.created"},
		{"draft", "/v1/questionnaire-drafts", fmt.Sprintf(`{"template_id":%q,"product_id":%q,"release_id":%q}`, f.template.ID, f.product.ID, f.release.ID), "questionnaire_draft.created"},
	}
}
func summaryDraftFixtureHuman(f questionnaireFixtureScope) domain.Actor {
	return domain.Actor{TenantID: f.actor.TenantID, UserID: "fixture-human", Scopes: []string{"report:read", "package:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: f.product.ID, Scopes: []string{"report:read", "package:read"}}}}
}
func TestSummaryDraftFixturesRollBackAllReportCitationAuditAndReplayEffects(t *testing.T) {
	for index := 0; index < 2; index++ {
		ledger, factory := integrationRegressionLedger()
		owner := seedQuestionnaireFixtureScope(t, ledger, "Owner")
		req := summaryDraftFixtureRequests(owner)[index]
		t.Run(req.name, func(t *testing.T) {
			s, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			s.authn = &configuredAuthenticator{actor: summaryDraftFixtureHuman(owner)}
			f := &failingSummaryDraftFixture{summaryDraftFixtureCommands: summaryDraftFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			s.evidenceSummaryCommands, s.questionnaireDraftCommands = f, f
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, s, "fixture-auth", req.path, "failed", []byte(req.body), 500)
			if f.changedID == "" || !f.isolated || strings.Contains(out, f.changedID) || strings.Contains(out, "private summary") || strings.Contains(out, `"data"`) {
				t.Fatal("failure bypassed real isolated writes or leaked report", out)
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != 1 {
				t.Fatal("missing failed replay marker", err)
			}
			for _, r := range after.Idempotency {
				if r.State != app.IdempotencyFailed || r.Response != nil || r.Status != 0 {
					t.Fatal("failed report retained response")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed report committed citations, report, audit or other effects")
			}
		})
	}
}
func TestSummaryDraftFixturesPreserveCompleteDTOCitationsHashAndCurrentReplayAuthority(t *testing.T) {
	for index := 0; index < 2; index++ {
		ledger, factory := integrationRegressionLedger()
		owner, foreign := seedQuestionnaireFixtureScope(t, ledger, "Owner"), seedQuestionnaireFixtureScope(t, ledger, "Foreign")
		req := summaryDraftFixtureRequests(owner)[index]
		t.Run(req.name, func(t *testing.T) {
			s, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			human := summaryDraftFixtureHuman(owner)
			auth := &configuredAuthenticator{actor: human}
			s.authn = auth
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			first := postRaw(t, s, "fixture-auth", req.path, "same", []byte(req.body), 201)
			id := dataField(t, first, "id")
			saved, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			var value any
			hash := ""
			if req.name == "summary" {
				v := saved.EvidenceSummaries[id]
				value = v
				if v.ID != id || v.TenantID != human.TenantID || v.SubjectType != "release" || v.SubjectID != owner.release.ID || len(v.Citations) != 1 || v.Citations[0] != (domain.EvidenceCitation{EvidenceID: owner.evidence.ID, Type: owner.evidence.Type, Title: owner.evidence.Title, CanonicalHash: owner.evidence.CanonicalHash}) || !reflect.DeepEqual(v.EvidenceIDs, []string{owner.evidence.ID}) || len(v.Assumptions) == 0 || len(v.Limitations) == 0 || len(saved.EvidenceSummaries) != len(before.EvidenceSummaries)+1 {
					t.Fatal("summary lost scope, complete citations or non-claims")
				}
			} else {
				v := saved.QuestionnaireDrafts[id]
				value, hash = v, v.ManifestHash
				computed, err := packageapp.HashQuestionnaireResponses(draftFixtureModel(v).Responses)
				if err != nil || computed != hash || v.TemplateID != owner.template.ID || v.ProductID != owner.product.ID || v.ReleaseID != owner.release.ID || len(v.Responses) != 1 || v.Responses[0].Answer != owner.entry.Answer || !reflect.DeepEqual(v.Responses[0].EvidenceIDs, owner.entry.EvidenceIDs) || len(v.Limitations) == 0 || len(saved.QuestionnaireDrafts) != len(before.QuestionnaireDrafts)+1 {
					t.Fatal("draft lost ranked answer, scope, citations, hash or limitations", err)
				}
			}
			want, err := json.Marshal(map[string]any{"data": value, "meta": map[string]string{"api_version": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, string(want), first)
			if len(saved.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || len(saved.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("report did not commit exactly one audit/replay")
			}
			last := saved.AuditEntries[human.TenantID][len(saved.AuditEntries[human.TenantID])-1]
			if last.EntryType != req.audit || last.SubjectID != id || last.ActorType != "human_user" || last.ActorID != human.UserID || last.PayloadHash != hash {
				t.Fatal("report audit lost actor, subject or hash binding")
			}
			assertTrustHTTPReplay(t, first, postRaw(t, s, "fixture-auth", req.path, "same", []byte(req.body), 201))
			if req.name == "draft" {
				auth.actor.Scopes = append(auth.actor.Scopes, "evidence:read")
				postRaw(t, s, "fixture-auth", req.path, "same", []byte(req.body), 409)
			}
			auth.actor = human
			postRaw(t, s, "fixture-auth", req.path, "same", append([]byte(req.body), ' '), 409)
			auth.actor.ResourceGrants = nil
			postRaw(t, s, "fixture-auth", req.path, "same", []byte(req.body), 403)
			postRaw(t, s, "fixture-auth", req.path, "denied-fresh", []byte(req.body), 403)
			auth.actor = human
			for local, wrong := range map[string]string{owner.release.ID: foreign.release.ID, owner.product.ID: foreign.product.ID, owner.template.ID: foreign.template.ID} {
				if strings.Contains(req.body, local) {
					postRaw(t, s, "fixture-auth", req.path, "foreign-"+local, []byte(strings.ReplaceAll(req.body, local, wrong)), 404)
				}
			}
			auth.err = app.ErrUnauthorized
			postRaw(t, s, "fixture-auth", req.path, "same", []byte(req.body), 401)
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(saved, after) {
				t.Fatal("saved replay/conflicts/current grants/foreign roots changed state", err)
			}
		})
	}
}
func TestSummaryDraftFixtureGuardsArePureCancellableAndKeepExplicitBindings(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedQuestionnaireFixtureScope(t, ledger, "Owner")
	f := summaryDraftFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []func(context.Context) error{
		func(ctx context.Context) error {
			return f.AuthorizeCreateEvidenceSummary(ctx, summaryDraftFixtureHuman(owner), packageapp.CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: owner.release.ID, EvidenceIDs: []string{owner.evidence.ID}})
		},
		func(ctx context.Context) error {
			return f.AuthorizeCreateQuestionnaireDraft(ctx, summaryDraftFixtureHuman(owner), packageapp.CreateQuestionnaireDraftInput{TemplateID: owner.template.ID, ProductID: owner.product.ID, ReleaseID: owner.release.ID})
		},
	} {
		if err := guard(t.Context()); err != nil {
			t.Fatal("owned pure guard failed", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := guard(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("report guard ignored cancellation", err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("report preflight wrote state", err)
	}
	summaries, drafts := &summaryHTTPFake{}, &draftHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{EvidenceSummaryCommands: summaries, QuestionnaireDraftCommands: drafts, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	s.bindLegacyLedgerFixture(newLegacyLedgerFixture(app.Config{}))
	if s.evidenceSummaryCommands != summaries || s.questionnaireDraftCommands != drafts {
		t.Fatal("binder replaced explicit report ports")
	}
}
func TestSummaryDraftFixtureMappingsPreserveCompleteDetachedMetadata(t *testing.T) {
	ledger, _ := integrationRegressionLedger()
	owner := seedQuestionnaireFixtureScope(t, ledger, "Owner")
	f := summaryDraftFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	summary, err := f.CreateEvidenceSummary(t.Context(), owner.actor, packageapp.CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: owner.release.ID, EvidenceIDs: []string{owner.evidence.ID}})
	if err != nil {
		t.Fatal(err)
	}
	draft, err := f.CreateQuestionnaireDraft(t.Context(), owner.actor, packageapp.CreateQuestionnaireDraftInput{TemplateID: owner.template.ID, ProductID: owner.product.ID, ReleaseID: owner.release.ID})
	if err != nil {
		t.Fatal(err)
	}
	originalSummary := domain.EvidenceSummary{ID: summary.ID, TenantID: summary.TenantID, SubjectType: summary.SubjectType, SubjectID: summary.SubjectID, EvidenceIDs: summary.EvidenceIDs, Summary: summary.Summary, Citations: []domain.EvidenceCitation{{EvidenceID: summary.Citations[0].EvidenceID, Type: summary.Citations[0].Type, Title: summary.Citations[0].Title, CanonicalHash: summary.Citations[0].CanonicalHash}}, Assumptions: summary.Assumptions, Limitations: summary.Limitations, SchemaVersion: summary.SchemaVersion, CreatedAt: summary.CreatedAt}
	originalDraft := domain.QuestionnaireDraft{ID: draft.ID, TenantID: draft.TenantID, TemplateID: draft.TemplateID, ProductID: draft.ProductID, ReleaseID: draft.ReleaseID, Responses: []domain.QuestionnaireResponse{{QuestionID: draft.Responses[0].QuestionID, Answer: draft.Responses[0].Answer, EvidenceIDs: draft.Responses[0].EvidenceIDs, Limitations: draft.Responses[0].Limitations}}, ManifestHash: draft.ManifestHash, Limitations: draft.Limitations, SchemaVersion: draft.SchemaVersion, CreatedAt: draft.CreatedAt}
	for _, pair := range []struct {
		original any
		encode   func() ([]byte, error)
	}{{originalSummary, func() ([]byte, error) { return packageapp.EncodeEvidenceSummary(summaryFixtureModel(originalSummary)) }}, {originalDraft, func() ([]byte, error) { return packageapp.EncodeQuestionnaireDraft(draftFixtureModel(originalDraft)) }}} {
		want, err := json.Marshal(pair.original)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pair.encode()
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(want), string(got))
	}
	sm, dm := summaryFixtureModel(originalSummary), draftFixtureModel(originalDraft)
	sm.EvidenceIDs[0], sm.Citations[0].Title, sm.Assumptions[0], sm.Limitations[0] = "changed", "changed", "changed", "changed"
	dm.Responses[0].EvidenceIDs[0], dm.Responses[0].Limitations[0], dm.Limitations[0] = "changed", "changed", "changed"
	if originalSummary.EvidenceIDs[0] != owner.evidence.ID || originalSummary.Citations[0].Title != owner.evidence.Title || strings.Contains(originalSummary.Assumptions[0], "changed") || strings.Contains(originalSummary.Limitations[0], "changed") || originalDraft.Responses[0].EvidenceIDs[0] != owner.evidence.ID || strings.Contains(originalDraft.Responses[0].Limitations[0], "changed") || strings.Contains(originalDraft.Limitations[0], "changed") {
		t.Fatal("report mappings share nested metadata")
	}
}
