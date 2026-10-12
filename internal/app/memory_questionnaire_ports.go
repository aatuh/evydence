package app

import (
	"context"
	"slices"
	"sort"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// These transaction-owned memory ports support focused-service tests. They do
// not read Ledger maps or constitute SQL row-locking/durability evidence.
func memoryQuestionnaireControl(state *MemoryUnitOfWorkSnapshot, tenant, id string) error {
	c, ok := state.SecurityControls[id]
	f, exists := state.ControlFrameworks[c.FrameworkID]
	if !ok || c.ID != id || c.TenantID != tenant || !exists || f.ID != c.FrameworkID || f.TenantID != tenant {
		return ErrNotFound
	}
	if !memoryMembershipQueryText(c.FrameworkID, 1024) {
		return ErrConflict
	}
	return nil
}

func (r memoryEnterpriseRepository) ValidateQuestionnaireTemplateScope(ctx context.Context, tenant string, ids []string) error {
	if len(ids) > packageapp.MaxQuestionnaireTemplateQuestions {
		return ErrValidation
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !memoryMembershipQueryText(id, packageapp.MaxQuestionnaireTemplateTextBytes) || seen[id] {
			return ErrValidation
		}
		seen[id] = true
	}
	return memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		for _, id := range ids {
			if err := memoryQuestionnaireControl(state, tenant, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r memoryEnterpriseRepository) ReadQuestionnairePackageScope(ctx context.Context, tenant string, in packageapp.CreateQuestionnairePackageInput) (packageapp.QuestionnairePackageScope, error) {
	var out packageapp.QuestionnairePackageScope
	in, err := packageapp.NormalizeQuestionnairePackageInput(in)
	if err != nil {
		return out, ErrValidation
	}
	out.Selection, err = memoryFutureExtensionsRepository(r).ReadQuestionnaireDraftScope(ctx, tenant, packageapp.CreateQuestionnaireDraftInput{TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	if err != nil {
		return out, err
	}
	if in.PackageID != "" {
		err = memoryGovernanceRead(ctx, r.uow, tenant, in.PackageID, func(state *MemoryUnitOfWorkSnapshot) error {
			s, err := memorySummaryScope(state, tenant, "customer_package", in.PackageID)
			if err != nil {
				return err
			}
			out.PackageID, out.PackageResources = in.PackageID, s.Resources
			return nil
		})
		if err != nil {
			return packageapp.QuestionnairePackageScope{}, err
		}
	}
	if err := packageapp.ValidateQuestionnairePackageScope(tenant, in, out); err != nil {
		return packageapp.QuestionnairePackageScope{}, fromPackageContextError(err)
	}
	return out, nil
}

func (r memoryFutureExtensionsRepository) ReadQuestionnaireDraftQuestions(ctx context.Context, s packageapp.QuestionnaireDraftScope) ([]packageapp.DraftQuestion, error) {
	out := []packageapp.DraftQuestion{}
	err := memoryGovernanceRead(ctx, r.uow, s.TenantID, s.TemplateID, func(state *MemoryUnitOfWorkSnapshot) error {
		t, ok := state.QuestionnaireTemplates[s.TemplateID]
		if !ok || t.ID != s.TemplateID || t.TenantID != s.TenantID {
			return ErrNotFound
		}
		if len(t.Questions) == 0 || len(t.Questions) > packageapp.MaxQuestionnaireDraftQuestions {
			return ErrValidation
		}
		for _, q := range t.Questions {
			if !memoryMembershipQueryText(q.ID, 1024) || !memoryMembershipText(q.ControlID, 1024) || !memoryMembershipText(q.EvidenceType, 1024) {
				return ErrConflict
			}
			out = append(out, packageapp.DraftQuestion{ID: q.ID, ControlID: q.ControlID, EvidenceType: q.EvidenceType})
		}
		return nil
	})
	return out, err
}

func (r memoryFutureExtensionsRepository) ReadQuestionnaireDraftCandidates(ctx context.Context, s packageapp.QuestionnaireDraftScope, q packageapp.DraftQuestion, remaining int) ([]packageapp.DraftAnswerCandidate, error) {
	if remaining < 0 || remaining > packageapp.MaxQuestionnaireDraftFacts {
		return nil, ErrValidation
	}
	out := []packageapp.DraftAnswerCandidate{}
	err := memoryIdentityRepository(r).membershipRead(ctx, s.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		bytes := 0
		for key, e := range state.AnswerLibrary {
			if e.TenantID != s.TenantID || e.ProductID != "" && e.ProductID != s.ProductID || e.ReleaseID != "" && e.ReleaseID != s.ReleaseID {
				continue
			}
			c := packageapp.DraftAnswerCandidate{ID: e.ID, TenantID: e.TenantID, QuestionID: e.QuestionID, ControlID: e.ControlID, EvidenceType: e.EvidenceType, ProductID: e.ProductID, ReleaseID: e.ReleaseID, CreatedAt: e.CreatedAt}
			if !packageapp.DraftAnswerMatchesQuestion(c, q) {
				continue
			}
			if e.ID != key {
				return ErrConflict
			}
			for _, value := range []string{e.ID, e.QuestionID, e.ControlID, e.EvidenceType, e.ProductID, e.ReleaseID} {
				if !memoryMembershipText(value, 1024) {
					return ErrConflict
				}
				bytes += len(value)
			}
			refs, err := memoryOperationsCoordinates(state, s.TenantID, application.ResourceReferences{ProductID: e.ProductID, ReleaseID: e.ReleaseID})
			if err != nil {
				continue
			}
			if e.ControlID != "" {
				if err := memoryQuestionnaireControl(state, s.TenantID, e.ControlID); err != nil {
					continue
				}
			}
			if len(out) == remaining || bytes > packageapp.MaxGeneratedReportBytes {
				return ErrValidation
			}
			c.Resources = application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID}
			out = append(out, c)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

func (r memoryFutureExtensionsRepository) ReadQuestionnaireDraftAnswer(ctx context.Context, s packageapp.QuestionnaireDraftScope, id string) (packageapp.DraftAnswer, error) {
	var out packageapp.DraftAnswer
	err := memoryGovernanceRead(ctx, r.uow, s.TenantID, id, func(state *MemoryUnitOfWorkSnapshot) error {
		e, ok := state.AnswerLibrary[id]
		if !ok || e.ID != id || e.TenantID != s.TenantID {
			return ErrNotFound
		}
		if !memoryMembershipText(e.Answer, packageapp.MaxQuestionnaireDraftAnswerBytes) || len(e.EvidenceIDs) > packageapp.MaxQuestionnaireDraftFacts || len(e.Limitations) > packageapp.MaxQuestionnaireDraftLimitations {
			return ErrValidation
		}
		bytes := len(e.Answer)
		for _, value := range e.EvidenceIDs {
			if !memoryMembershipQueryText(value, 1024) {
				return ErrValidation
			}
			bytes += len(value)
		}
		for _, value := range e.Limitations {
			if !memoryMembershipText(value, packageapp.MaxQuestionnaireDraftAnswerBytes) {
				return ErrValidation
			}
			bytes += len(value)
		}
		if bytes > packageapp.MaxGeneratedReportBytes {
			return ErrValidation
		}
		out = packageapp.DraftAnswer{ID: id, TenantID: s.TenantID, Answer: e.Answer, EvidenceIDs: slices.Clone(e.EvidenceIDs), Limitations: slices.Clone(e.Limitations)}
		return nil
	})
	return out, err
}

func (r memoryFutureExtensionsRepository) ReadQuestionnaireDraftEvidence(ctx context.Context, s packageapp.QuestionnaireDraftScope, q packageapp.DraftQuestion, remaining int) ([]string, error) {
	if remaining < 0 || remaining > packageapp.MaxQuestionnaireDraftFacts {
		return nil, ErrValidation
	}
	out := []string{}
	err := memoryIdentityRepository(r).membershipRead(ctx, s.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		add := func(id string) error {
			if !memoryMembershipQueryText(id, 1024) {
				return ErrConflict
			}
			if len(out) == remaining {
				return ErrValidation
			}
			out = append(out, id)
			return nil
		}
		if q.ControlID != "" {
			for _, link := range state.ControlEvidence {
				if link.TenantID != s.TenantID || link.ControlID != q.ControlID || link.SubjectType != "evidence" || s.ProductID != "" && link.ProductID != "" && link.ProductID != s.ProductID || s.ReleaseID != "" && link.ReleaseID != "" && link.ReleaseID != s.ReleaseID {
					continue
				}
				if err := add(link.SubjectID); err != nil {
					return err
				}
			}
		} else {
			for key, e := range state.Evidence {
				if e.TenantID != s.TenantID || s.ProductID != "" && e.ProductID != s.ProductID || s.ReleaseID != "" && e.ReleaseID != s.ReleaseID || q.EvidenceType != "" && e.Type != q.EvidenceType {
					continue
				}
				if e.ID != key {
					return ErrConflict
				}
				if err := add(e.ID); err != nil {
					return err
				}
			}
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func (r memoryFutureExtensionsRepository) ValidateQuestionnaireDraftEvidence(ctx context.Context, s packageapp.QuestionnaireDraftScope, ids []string) error {
	if len(ids) > packageapp.MaxQuestionnaireDraftFacts {
		return ErrValidation
	}
	return memoryIdentityRepository(r).membershipRead(ctx, s.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		for _, id := range ids {
			if !memoryMembershipQueryText(id, 1024) {
				return ErrValidation
			}
			e, ok := state.Evidence[id]
			if !ok || e.ID != id || e.TenantID != s.TenantID {
				return ErrNotFound
			}
			refs, err := memoryOperationsCoordinates(state, s.TenantID, application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID, BuildID: e.BuildID, DeploymentID: e.DeploymentID})
			if err != nil {
				return ErrNotFound
			}
			if s.Resources.ProductID != "" && refs.ProductID != s.Resources.ProductID || s.ReleaseID != "" && refs.ReleaseID != s.ReleaseID {
				return ErrNotFound
			}
		}
		return nil
	})
}

func legacyQuestionnaireResponses(values []packagedomain.QuestionnaireResponse) []domain.QuestionnaireResponse {
	out := make([]domain.QuestionnaireResponse, len(values))
	for i, v := range values {
		out[i] = domain.QuestionnaireResponse{QuestionID: v.QuestionID, Answer: v.Answer, EvidenceIDs: slices.Clone(v.EvidenceIDs), Limitations: slices.Clone(v.Limitations)}
	}
	return out
}

func (r memoryEnterpriseRepository) InsertFocusedQuestionnaireTemplate(ctx context.Context, v packagedomain.QuestionnaireTemplate) error {
	if err := packageapp.ValidateQuestionnaireTemplateRecord(v); err != nil {
		return fromPackageContextError(err)
	}
	if err := r.ValidateQuestionnaireTemplateScope(ctx, v.TenantID, packageapp.QuestionnaireTemplateControlIDs(v.Questions)); err != nil {
		return err
	}
	qs := make([]domain.QuestionnaireQuestion, len(v.Questions))
	for i, q := range v.Questions {
		qs[i] = domain.QuestionnaireQuestion{ID: q.ID, Prompt: q.Prompt, ControlID: q.ControlID, EvidenceType: q.EvidenceType, AllowedFields: slices.Clone(q.AllowedFields)}
	}
	return r.InsertQuestionnaireTemplate(ctx, domain.QuestionnaireTemplate{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Version: v.Version, Questions: qs, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}
func (r memoryEnterpriseRepository) InsertFocusedQuestionnairePackage(ctx context.Context, v packagedomain.QuestionnairePackage) error {
	if err := packageapp.ValidateQuestionnairePackageRecord(v); err != nil {
		return fromPackageContextError(err)
	}
	s, err := r.ReadQuestionnairePackageScope(ctx, v.TenantID, packageapp.CreateQuestionnairePackageInput{TemplateID: v.TemplateID, PackageID: v.PackageID, ProductID: v.ProductID, ReleaseID: v.ReleaseID})
	if err != nil {
		return err
	}
	if err := validateMemoryFocusedQuestionnaireResponses(ctx, memoryFutureExtensionsRepository(r), s.Selection, v.Responses); err != nil {
		return err
	}
	return r.InsertQuestionnairePackage(ctx, domain.QuestionnairePackage{ID: v.ID, TenantID: v.TenantID, TemplateID: v.TemplateID, PackageID: v.PackageID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Responses: legacyQuestionnaireResponses(v.Responses), ManifestHash: v.ManifestHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}
func (r memoryFutureExtensionsRepository) InsertFocusedQuestionnaireDraft(ctx context.Context, v packagedomain.QuestionnaireDraft) error {
	if err := packageapp.ValidateQuestionnaireDraftRecord(v); err != nil {
		return fromPackageContextError(err)
	}
	s, err := r.ReadQuestionnaireDraftScope(ctx, v.TenantID, packageapp.CreateQuestionnaireDraftInput{TemplateID: v.TemplateID, ProductID: v.ProductID, ReleaseID: v.ReleaseID})
	if err != nil {
		return err
	}
	if err := validateMemoryFocusedQuestionnaireResponses(ctx, r, s, v.Responses); err != nil {
		return err
	}
	return r.InsertQuestionnaireDraft(ctx, domain.QuestionnaireDraft{ID: v.ID, TenantID: v.TenantID, TemplateID: v.TemplateID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Responses: legacyQuestionnaireResponses(v.Responses), ManifestHash: v.ManifestHash, Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}

func validateMemoryFocusedQuestionnaireResponses(ctx context.Context, r memoryFutureExtensionsRepository, s packageapp.QuestionnaireDraftScope, values []packagedomain.QuestionnaireResponse) error {
	qs, err := r.ReadQuestionnaireDraftQuestions(ctx, s)
	if err != nil {
		return err
	}
	if len(qs) != len(values) {
		return ErrValidation
	}
	n := 0
	for i, v := range values {
		if v.QuestionID != qs[i].ID {
			return ErrValidation
		}
		n += len(v.EvidenceIDs)
		if n > packageapp.MaxQuestionnaireDraftFacts {
			return ErrValidation
		}
		if err := r.ValidateQuestionnaireDraftEvidence(ctx, s, v.EvidenceIDs); err != nil {
			return err
		}
	}
	return nil
}

var _ packageapp.QuestionnaireDraftReader = memoryFutureExtensionsRepository{}
var _ packageapp.QuestionnairePackageReader = memoryEnterpriseRepository{}
