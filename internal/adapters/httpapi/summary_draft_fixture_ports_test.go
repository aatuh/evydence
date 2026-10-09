package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Summaries and drafts use focused commands on transaction repositories. These
// fixtures are not a runtime backend or evidence of SQL bounds or durability.
type summaryDraftFixtureCommands struct{ catalogFixtureCommands }

func (f summaryDraftFixtureCommands) AuthorizeCreateEvidenceSummary(ctx context.Context, a domain.Actor, in packageapp.CreateEvidenceSummaryInput) error {
	g, err := f.nativeSummary(true)
	if err != nil {
		return err
	}
	return g.AuthorizeCreateEvidenceSummary(ctx, a, in)
}
func (f summaryDraftFixtureCommands) AuthorizeCreateQuestionnaireDraft(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnaireDraftInput) error {
	g, err := f.nativeDraft(true)
	if err != nil {
		return err
	}
	return g.AuthorizeCreateQuestionnaireDraft(ctx, a, in)
}
func summaryFixtureModel(v domain.EvidenceSummary) packagedomain.EvidenceSummary {
	citations := make([]packagedomain.EvidenceCitation, len(v.Citations))
	for i, c := range v.Citations {
		citations[i] = packagedomain.EvidenceCitation{EvidenceID: c.EvidenceID, Type: c.Type, Title: c.Title, CanonicalHash: c.CanonicalHash}
	}
	return packagedomain.EvidenceSummary{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, EvidenceIDs: slices.Clone(v.EvidenceIDs), Summary: v.Summary, Citations: citations, Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func draftFixtureModel(v domain.QuestionnaireDraft) packagedomain.QuestionnaireDraft {
	responses := make([]packagedomain.QuestionnaireResponse, len(v.Responses))
	for i, r := range v.Responses {
		responses[i] = packagedomain.QuestionnaireResponse{QuestionID: r.QuestionID, Answer: r.Answer, EvidenceIDs: slices.Clone(r.EvidenceIDs), Limitations: slices.Clone(r.Limitations)}
	}
	return packagedomain.QuestionnaireDraft{ID: v.ID, TenantID: v.TenantID, TemplateID: v.TemplateID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Responses: responses, ManifestHash: v.ManifestHash, Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func (f summaryDraftFixtureCommands) CreateEvidenceSummary(ctx context.Context, a domain.Actor, in packageapp.CreateEvidenceSummaryInput) (packagedomain.EvidenceSummary, error) {
	c, err := f.nativeSummary(false)
	if err != nil {
		return packagedomain.EvidenceSummary{}, err
	}
	return c.CreateEvidenceSummary(ctx, a, in)
}
func (f summaryDraftFixtureCommands) CreateQuestionnaireDraft(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnaireDraftInput) (packagedomain.QuestionnaireDraft, error) {
	c, err := f.nativeDraft(false)
	if err != nil {
		return packagedomain.QuestionnaireDraft{}, err
	}
	return c.CreateQuestionnaireDraft(ctx, a, in)
}
func (s *Server) bindSummaryDraftFixturePorts(ledger *app.Ledger) {
	f := summaryDraftFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.evidenceSummaryCommands.(summaryDraftFixtureCommands); s.evidenceSummaryCommands == nil || fixture {
		s.evidenceSummaryCommands = f
	}
	if _, fixture := s.questionnaireDraftCommands.(summaryDraftFixtureCommands); s.questionnaireDraftCommands == nil || fixture {
		s.questionnaireDraftCommands = f
	}
}

var (
	_ EvidenceSummaryCommands    = summaryDraftFixtureCommands{}
	_ QuestionnaireDraftCommands = summaryDraftFixtureCommands{}
)
