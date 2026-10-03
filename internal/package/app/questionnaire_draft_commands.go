package app

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const (
	MaxQuestionnaireDraftQuestions   = 512
	MaxQuestionnaireDraftFacts       = 4096
	MaxQuestionnaireDraftAnswerBytes = 64 << 10
	MaxQuestionnaireDraftIDBytes     = 1024
	MaxQuestionnaireDraftLimitations = 128
)

type CreateQuestionnaireDraftInput struct{ TemplateID, ProductID, ReleaseID string }
type QuestionnaireDraftScope struct {
	TenantID, TemplateID, ProductID, ReleaseID string
	Resources                                  application.ResourceReferences
}

// Prompts and allowed-field metadata are not needed to draft these answers.
type DraftQuestion struct{ ID, ControlID, EvidenceType string }

// Selection metadata only: private answer text is fetched after authorization.
type DraftAnswerCandidate struct {
	ID, TenantID, QuestionID, ControlID, EvidenceType, ProductID, ReleaseID string
	Resources                                                               application.ResourceReferences
	CreatedAt                                                               time.Time
}
type DraftAnswer struct {
	ID, TenantID, Answer     string
	EvidenceIDs, Limitations []string
}

type QuestionnaireDraftReader interface {
	ReadQuestionnaireDraftScope(context.Context, string, CreateQuestionnaireDraftInput) (QuestionnaireDraftScope, error)
	ReadQuestionnaireDraftQuestions(context.Context, QuestionnaireDraftScope) ([]DraftQuestion, error)
	ReadQuestionnaireDraftCandidates(context.Context, QuestionnaireDraftScope, DraftQuestion, int) ([]DraftAnswerCandidate, error)
	ReadQuestionnaireDraftAnswer(context.Context, QuestionnaireDraftScope, string) (DraftAnswer, error)
	ReadQuestionnaireDraftEvidence(context.Context, QuestionnaireDraftScope, DraftQuestion, int) ([]string, error)
	ValidateQuestionnaireDraftEvidence(context.Context, QuestionnaireDraftScope, []string) error
}
type QuestionnaireDraftTransaction interface {
	QuestionnaireDraftReader
	InsertQuestionnaireDraft(context.Context, packagedomain.QuestionnaireDraft) error
	application.Authorizer
	application.AuditAppender
}
type QuestionnaireDraftTransactions interface {
	ExecuteQuestionnaireDraft(context.Context, string, func(context.Context, QuestionnaireDraftTransaction) error) error
}
type QuestionnaireDraftCommandConfig struct {
	Transactions QuestionnaireDraftTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type QuestionnaireDraftCommands struct {
	config QuestionnaireDraftCommandConfig
}

func NewQuestionnaireDraftCommands(c QuestionnaireDraftCommandConfig) (*QuestionnaireDraftCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &QuestionnaireDraftCommands{c}, nil
}
func NormalizeQuestionnaireDraftInput(in CreateQuestionnaireDraftInput) (CreateQuestionnaireDraftInput, error) {
	for _, id := range []string{in.TemplateID, in.ProductID, in.ReleaseID} {
		if !draftText(id, MaxQuestionnaireDraftIDBytes, false) {
			return in, ErrValidation
		}
	}
	in.TemplateID, in.ProductID, in.ReleaseID = strings.TrimSpace(in.TemplateID), strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	if !draftText(in.TemplateID, MaxQuestionnaireDraftIDBytes, true) || !draftText(in.ProductID, MaxQuestionnaireDraftIDBytes, false) || !draftText(in.ReleaseID, MaxQuestionnaireDraftIDBytes, false) {
		return in, ErrValidation
	}
	return in, nil
}
func draftText(v string, max int, required bool) bool {
	return (!required || strings.TrimSpace(v) != "") && len(v) <= max && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func (s *QuestionnaireDraftCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateQuestionnaireDraftInput) (CreateQuestionnaireDraftInput, error) {
	if s == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	in, err := NormalizeQuestionnaireDraftInput(in)
	if err != nil {
		return in, err
	}
	return in, s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageRead, ScopeOnly: true})
}
func readAuthorizedDraftScope(ctx context.Context, tx QuestionnaireDraftTransaction, a identitydomain.Actor, in CreateQuestionnaireDraftInput) (QuestionnaireDraftScope, error) {
	s, err := tx.ReadQuestionnaireDraftScope(ctx, a.TenantID, in)
	if err != nil {
		return s, err
	}
	if s.TenantID != a.TenantID || s.TemplateID != in.TemplateID || s.ProductID != in.ProductID || s.ReleaseID != in.ReleaseID {
		return s, ErrNotFound
	}
	refs := s.Resources
	if refs != (application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID}) || refs.ReleaseID != in.ReleaseID || in.ProductID != "" && refs.ProductID != in.ProductID || refs.ReleaseID != "" && refs.ProductID == "" || in.ProductID == "" && in.ReleaseID == "" && refs.ProductID != "" {
		return s, ErrConflict
	}
	return s, tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageRead, Resources: s.Resources, TenantWide: s.Resources == (application.ResourceReferences{})})
}
func (s *QuestionnaireDraftCommands) AuthorizeCreateQuestionnaireDraft(ctx context.Context, a identitydomain.Actor, in CreateQuestionnaireDraftInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteQuestionnaireDraft(ctx, a.TenantID, func(ctx context.Context, tx QuestionnaireDraftTransaction) error {
		_, err := readAuthorizedDraftScope(ctx, tx, a, in)
		return err
	})
}

func (s *QuestionnaireDraftCommands) CreateQuestionnaireDraft(ctx context.Context, a identitydomain.Actor, in CreateQuestionnaireDraftInput) (packagedomain.QuestionnaireDraft, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return packagedomain.QuestionnaireDraft{}, err
	}
	var result packagedomain.QuestionnaireDraft
	err = s.config.Transactions.ExecuteQuestionnaireDraft(ctx, a.TenantID, func(ctx context.Context, tx QuestionnaireDraftTransaction) error {
		scope, err := readAuthorizedDraftScope(ctx, tx, a, in)
		if err != nil {
			return err
		}
		questions, err := tx.ReadQuestionnaireDraftQuestions(ctx, scope)
		if err != nil {
			return err
		}
		if len(questions) == 0 || len(questions) > MaxQuestionnaireDraftQuestions {
			return ErrValidation
		}
		seen := make(map[string]bool, len(questions))
		metadataBytes := 0
		for _, q := range questions {
			if !draftText(q.ID, MaxQuestionnaireDraftIDBytes, true) || !draftText(q.ControlID, MaxQuestionnaireDraftIDBytes, false) || !draftText(q.EvidenceType, MaxQuestionnaireDraftIDBytes, false) {
				return ErrValidation
			}
			if seen[q.ID] {
				return ErrConflict
			}
			seen[q.ID] = true
			metadataBytes += len(q.ID) + len(q.ControlID) + len(q.EvidenceType)
		}
		responses := make([]packagedomain.QuestionnaireResponse, 0, len(questions))
		facts, citations, bytes := 0, 0, 0
		for _, q := range questions {
			if err := contextError(ctx); err != nil {
				return err
			}
			candidates, err := tx.ReadQuestionnaireDraftCandidates(ctx, scope, q, MaxQuestionnaireDraftFacts-facts)
			if err != nil {
				return err
			}
			facts += len(candidates)
			if facts > MaxQuestionnaireDraftFacts {
				return ErrValidation
			}
			for _, c := range candidates {
				metadataBytes += len(c.ID) + len(c.QuestionID) + len(c.ControlID) + len(c.EvidenceType) + len(c.ProductID) + len(c.ReleaseID)
				if metadataBytes > MaxGeneratedReportBytes {
					return ErrValidation
				}
			}
			winner, found, err := selectDraftAnswer(ctx, tx, a, scope, q, candidates)
			if err != nil {
				return err
			}
			r := packagedomain.QuestionnaireResponse{QuestionID: q.ID}
			if found {
				answer, err := tx.ReadQuestionnaireDraftAnswer(ctx, scope, winner.ID)
				if err != nil {
					return err
				}
				if answer.TenantID != a.TenantID {
					return ErrNotFound
				}
				if answer.ID != winner.ID {
					return ErrConflict
				}
				if !draftText(answer.Answer, MaxQuestionnaireDraftAnswerBytes, true) || len(answer.Limitations) > MaxQuestionnaireDraftLimitations {
					return ErrValidation
				}
				r.Answer = answer.Answer
				r.EvidenceIDs = append([]string(nil), answer.EvidenceIDs...)
				r.Limitations = append([]string(nil), answer.Limitations...)
			} else {
				ids, err := tx.ReadQuestionnaireDraftEvidence(ctx, scope, q, MaxQuestionnaireDraftFacts-citations)
				if err != nil {
					return err
				}
				r.EvidenceIDs = append([]string(nil), ids...)
				sort.Strings(r.EvidenceIDs)
				r.Answer = "No matching evidence is recorded for this question."
				if len(ids) > 0 {
					r.Answer = "Evidence is available for review in the linked evidence records."
				}
				r.Limitations = []string{"Questionnaire responses summarize recorded evidence and require human review."}
			}
			citations += len(r.EvidenceIDs)
			if citations > MaxQuestionnaireDraftFacts {
				return ErrValidation
			}
			for _, id := range r.EvidenceIDs {
				if !draftText(id, MaxQuestionnaireDraftIDBytes, true) {
					return ErrValidation
				}
			}
			for _, lim := range r.Limitations {
				if !draftText(lim, MaxQuestionnaireDraftAnswerBytes, false) {
					return ErrValidation
				}
			}
			if err := tx.ValidateQuestionnaireDraftEvidence(ctx, scope, r.EvidenceIDs); err != nil {
				return err
			}
			encoded, err := EncodeQuestionnaireResponses([]packagedomain.QuestionnaireResponse{r})
			if err != nil {
				return err
			}
			bytes += len(encoded)
			if bytes > MaxGeneratedReportBytes {
				return ErrValidation
			}
			responses = append(responses, r)
		}
		encoded, err := EncodeQuestionnaireResponses(responses)
		if err != nil {
			return err
		}
		hash, err := application.NormalizedJSONHash(json.RawMessage(encoded))
		if err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC()
		result = packagedomain.QuestionnaireDraft{ID: s.config.IDs.NewID("qdr"), TenantID: a.TenantID, TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Responses: responses, ManifestHash: hash, Limitations: []string{"Generated answers are drafts based on stored evidence and do not provide compliance conclusions."}, SchemaVersion: packagedomain.QuestionnaireDraftVersion, CreatedAt: now}
		if err := ValidateQuestionnaireDraftRecord(result); err != nil {
			return err
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertQuestionnaireDraft(ctx, cloneQuestionnaireDraft(result)); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "questionnaire_draft.created", SubjectType: "questionnaire_draft", SubjectID: result.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: now, PayloadHash: hash})
		if err != nil {
			return err
		}
		return contextError(ctx)
	})
	if err != nil {
		return packagedomain.QuestionnaireDraft{}, err
	}
	return cloneQuestionnaireDraft(result), nil
}

func selectDraftAnswer(ctx context.Context, tx application.Authorizer, a identitydomain.Actor, s QuestionnaireDraftScope, q DraftQuestion, candidates []DraftAnswerCandidate) (DraftAnswerCandidate, bool, error) {
	var winner DraftAnswerCandidate
	found := false
	seen := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		if c.TenantID != a.TenantID {
			return winner, false, ErrNotFound
		}
		if !draftText(c.ID, MaxQuestionnaireDraftIDBytes, true) || !draftText(c.QuestionID, MaxQuestionnaireDraftIDBytes, false) || !draftText(c.ControlID, MaxQuestionnaireDraftIDBytes, false) || !draftText(c.EvidenceType, MaxQuestionnaireDraftIDBytes, false) || !draftText(c.ProductID, MaxQuestionnaireDraftIDBytes, false) || !draftText(c.ReleaseID, MaxQuestionnaireDraftIDBytes, false) || c.CreatedAt.IsZero() {
			return winner, false, ErrConflict
		}
		if seen[c.ID] {
			return winner, false, ErrConflict
		}
		seen[c.ID] = true
		refs := application.ResourceReferences{ProductID: c.ProductID, ReleaseID: c.ReleaseID}
		if c.ReleaseID != "" {
			refs.ProductID = s.Resources.ProductID
		}
		if c.Resources != refs || c.ProductID != "" && c.ReleaseID != "" && c.ProductID != refs.ProductID {
			return winner, false, ErrConflict
		}
		if !DraftAnswerMatchesQuestion(c, q) || c.ProductID != "" && c.ProductID != s.ProductID || c.ReleaseID != "" && c.ReleaseID != s.ReleaseID {
			continue
		}
		err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageRead, Resources: c.Resources, TenantWide: c.Resources == (application.ResourceReferences{})})
		if errors.Is(err, application.ErrForbidden) {
			continue
		}
		if err != nil {
			return winner, false, err
		}
		if !found || draftAnswerBefore(c, winner, q) {
			winner = c
			found = true
		}
	}
	return winner, found, nil
}
func DraftAnswerMatchesQuestion(c DraftAnswerCandidate, q DraftQuestion) bool {
	return c.QuestionID != "" && c.QuestionID == q.ID || c.ControlID != "" && c.ControlID == q.ControlID || c.EvidenceType != "" && c.EvidenceType == q.EvidenceType
}
func DraftAnswerSpecificity(c DraftAnswerCandidate, q DraftQuestion) int {
	n := 0
	if c.QuestionID != "" && c.QuestionID == q.ID {
		n += 8
	}
	if c.ControlID != "" && c.ControlID == q.ControlID {
		n += 4
	}
	if c.EvidenceType != "" && c.EvidenceType == q.EvidenceType {
		n += 2
	}
	if c.ProductID != "" {
		n++
	}
	if c.ReleaseID != "" {
		n++
	}
	return n
}
func draftAnswerBefore(a, b DraftAnswerCandidate, q DraftQuestion) bool {
	x, y := DraftAnswerSpecificity(a, q), DraftAnswerSpecificity(b, q)
	if x != y {
		return x > y
	}
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.After(b.CreatedAt)
	}
	return a.ID < b.ID
}
func cloneQuestionnaireDraft(v packagedomain.QuestionnaireDraft) packagedomain.QuestionnaireDraft {
	v.Responses = append([]packagedomain.QuestionnaireResponse(nil), v.Responses...)
	for i := range v.Responses {
		v.Responses[i].EvidenceIDs = append([]string(nil), v.Responses[i].EvidenceIDs...)
		v.Responses[i].Limitations = append([]string(nil), v.Responses[i].Limitations...)
	}
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}

// ValidateQuestionnaireDraftRecord is shared by orchestration and persistence:
// selected responses and their versioned manifest hash cannot diverge.
func ValidateQuestionnaireDraftRecord(v packagedomain.QuestionnaireDraft) error {
	for _, id := range []string{v.ID, v.TenantID, v.TemplateID} {
		if !draftText(id, MaxQuestionnaireDraftIDBytes, true) {
			return ErrValidation
		}
	}
	if !draftText(v.ProductID, MaxQuestionnaireDraftIDBytes, false) || !draftText(v.ReleaseID, MaxQuestionnaireDraftIDBytes, false) || v.SchemaVersion != packagedomain.QuestionnaireDraftVersion || v.CreatedAt.IsZero() || v.CreatedAt.Year() < 1 || v.CreatedAt.Year() > 9999 || len(v.Responses) == 0 || len(v.Responses) > MaxQuestionnaireDraftQuestions {
		return ErrValidation
	}
	seen := make(map[string]bool, len(v.Responses))
	citations := 0
	for _, r := range v.Responses {
		if !draftText(r.QuestionID, MaxQuestionnaireDraftIDBytes, true) || seen[r.QuestionID] || !draftText(r.Answer, MaxQuestionnaireDraftAnswerBytes, true) || !validDraftLimitations(r.Limitations) {
			return ErrValidation
		}
		seen[r.QuestionID] = true
		citations += len(r.EvidenceIDs)
		if citations > MaxQuestionnaireDraftFacts {
			return ErrValidation
		}
		for _, id := range r.EvidenceIDs {
			if !draftText(id, MaxQuestionnaireDraftIDBytes, true) {
				return ErrValidation
			}
		}
	}
	if !validDraftLimitations(v.Limitations) {
		return ErrValidation
	}
	responses, err := EncodeQuestionnaireResponses(v.Responses)
	if err != nil {
		return err
	}
	if len(responses) > MaxGeneratedReportBytes {
		return ErrValidation
	}
	hash, err := application.NormalizedJSONHash(json.RawMessage(responses))
	if err != nil {
		return err
	}
	if hash != v.ManifestHash {
		return ErrValidation
	}
	public, err := EncodeQuestionnaireDraft(v)
	if err != nil {
		return err
	}
	if len(public) > MaxGeneratedReportBytes {
		return ErrValidation
	}
	return nil
}

func validDraftLimitations(values []string) bool {
	if len(values) > MaxQuestionnaireDraftLimitations {
		return false
	}
	for _, v := range values {
		if !draftText(v, MaxQuestionnaireDraftAnswerBytes, false) {
			return false
		}
	}
	return true
}
func questionnaireResponseDocument(v packagedomain.QuestionnaireResponse) map[string]any {
	out := map[string]any{"question_id": v.QuestionID, "answer": v.Answer}
	if len(v.EvidenceIDs) > 0 {
		out["evidence_ids"] = v.EvidenceIDs
	}
	if len(v.Limitations) > 0 {
		out["limitations"] = v.Limitations
	}
	return out
}

// The versioned response document preserves the legacy omitempty semantics
// used by the normalized-JSON manifest hash without domain transport tags.
func EncodeQuestionnaireResponses(values []packagedomain.QuestionnaireResponse) ([]byte, error) {
	out := make([]map[string]any, len(values))
	for i, v := range values {
		out[i] = questionnaireResponseDocument(v)
	}
	return json.Marshal(out)
}
func EncodeQuestionnaireDraft(v packagedomain.QuestionnaireDraft) ([]byte, error) {
	responses := make([]map[string]any, len(v.Responses))
	for i, r := range v.Responses {
		responses[i] = questionnaireResponseDocument(r)
	}
	out := map[string]any{"id": v.ID, "tenant_id": v.TenantID, "template_id": v.TemplateID, "responses": responses, "manifest_hash": v.ManifestHash, "limitations": v.Limitations, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt}
	if v.ProductID != "" {
		out["product_id"] = v.ProductID
	}
	if v.ReleaseID != "" {
		out["release_id"] = v.ReleaseID
	}
	return json.Marshal(out)
}
