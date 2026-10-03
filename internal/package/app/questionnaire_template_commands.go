package app

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const (
	MaxQuestionnaireTemplateQuestions   = 512
	MaxQuestionnaireTemplateFields      = 128
	MaxQuestionnaireTemplateTextBytes   = 1024
	MaxQuestionnaireTemplatePromptBytes = 64 << 10
)

type CreateQuestionnaireTemplateInput struct {
	Name, Version string
	Questions     []packagedomain.QuestionnaireQuestion
}

// This port locks only the tenant and selected control/framework identities.
// It cannot read existing templates, evidence payloads, or an answer library.
type QuestionnaireTemplateTransaction interface {
	ValidateQuestionnaireTemplateScope(context.Context, string, []string) error
	InsertQuestionnaireTemplate(context.Context, packagedomain.QuestionnaireTemplate) error
	application.AuditAppender
}
type QuestionnaireTemplateTransactions interface {
	ExecuteQuestionnaireTemplate(context.Context, string, func(context.Context, QuestionnaireTemplateTransaction) error) error
}
type QuestionnaireTemplateCommandConfig struct {
	Transactions QuestionnaireTemplateTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type QuestionnaireTemplateCommands struct {
	config QuestionnaireTemplateCommandConfig
}

func NewQuestionnaireTemplateCommands(c QuestionnaireTemplateCommandConfig) (*QuestionnaireTemplateCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &QuestionnaireTemplateCommands{config: c}, nil
}

func questionnaireTemplateText(v string, limit int) bool {
	return len(v) <= limit && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}

// Bounds apply before trimming, and before copying unbounded input slices.
// Question order and allowed-field duplicates/empty strings retain their legacy
// meaning: allowed_fields is inert metadata, not an authorization policy.
func NormalizeQuestionnaireTemplateInput(in CreateQuestionnaireTemplateInput) (CreateQuestionnaireTemplateInput, error) {
	if !questionnaireTemplateText(in.Name, MaxQuestionnaireTemplateTextBytes) || !questionnaireTemplateText(in.Version, MaxQuestionnaireTemplateTextBytes) || len(in.Questions) == 0 || len(in.Questions) > MaxQuestionnaireTemplateQuestions {
		return in, ErrValidation
	}
	bytes := len(in.Name) + len(in.Version)
	for _, q := range in.Questions {
		if !questionnaireTemplateText(q.ID, MaxQuestionnaireTemplateTextBytes) || !questionnaireTemplateText(q.Prompt, MaxQuestionnaireTemplatePromptBytes) || !questionnaireTemplateText(q.ControlID, MaxQuestionnaireTemplateTextBytes) || !questionnaireTemplateText(q.EvidenceType, MaxQuestionnaireTemplateTextBytes) || len(q.AllowedFields) > MaxQuestionnaireTemplateFields {
			return in, ErrValidation
		}
		bytes += len(q.ID) + len(q.Prompt) + len(q.ControlID) + len(q.EvidenceType)
		for _, field := range q.AllowedFields {
			if !questionnaireTemplateText(field, MaxQuestionnaireTemplateTextBytes) {
				return in, ErrValidation
			}
			bytes += len(field)
		}
		if bytes > MaxGeneratedReportBytes {
			return in, ErrValidation
		}
	}
	in.Name, in.Version = strings.TrimSpace(in.Name), strings.TrimSpace(in.Version)
	if in.Name == "" || in.Version == "" {
		return in, ErrValidation
	}
	in.Questions = cloneQuestionnaireQuestions(in.Questions)
	seen := make(map[string]bool, len(in.Questions))
	for i := range in.Questions {
		q := &in.Questions[i]
		q.ID, q.Prompt = strings.TrimSpace(q.ID), strings.TrimSpace(q.Prompt)
		q.ControlID, q.EvidenceType = strings.TrimSpace(q.ControlID), strings.TrimSpace(q.EvidenceType)
		if q.ID == "" || q.Prompt == "" || seen[q.ID] {
			return in, ErrValidation
		}
		seen[q.ID] = true
		for j := range q.AllowedFields {
			q.AllowedFields[j] = strings.TrimSpace(q.AllowedFields[j])
		}
		sort.Strings(q.AllowedFields)
	}
	return in, nil
}

func (s *QuestionnaireTemplateCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateQuestionnaireTemplateInput) (CreateQuestionnaireTemplateInput, error) {
	if s == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, TenantWide: true}); err != nil {
		return in, err
	}
	return NormalizeQuestionnaireTemplateInput(in)
}

func QuestionnaireTemplateControlIDs(qs []packagedomain.QuestionnaireQuestion) []string {
	ids := []string{}
	for _, q := range qs {
		if q.ControlID != "" {
			ids = append(ids, q.ControlID)
		}
	}
	sort.Strings(ids)
	return slices.Compact(ids)
}

// Replay checks current authority and referenced ownership without reading any
// template prompt or creating template/audit effects.
func (s *QuestionnaireTemplateCommands) AuthorizeCreateQuestionnaireTemplate(ctx context.Context, a identitydomain.Actor, in CreateQuestionnaireTemplateInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteQuestionnaireTemplate(ctx, a.TenantID, func(ctx context.Context, tx QuestionnaireTemplateTransaction) error {
		if err := tx.ValidateQuestionnaireTemplateScope(ctx, a.TenantID, QuestionnaireTemplateControlIDs(in.Questions)); err != nil {
			return err
		}
		return contextError(ctx)
	})
}

func (s *QuestionnaireTemplateCommands) CreateQuestionnaireTemplate(ctx context.Context, a identitydomain.Actor, in CreateQuestionnaireTemplateInput) (packagedomain.QuestionnaireTemplate, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return packagedomain.QuestionnaireTemplate{}, err
	}
	var result packagedomain.QuestionnaireTemplate
	err = s.config.Transactions.ExecuteQuestionnaireTemplate(ctx, a.TenantID, func(ctx context.Context, tx QuestionnaireTemplateTransaction) error {
		if err := tx.ValidateQuestionnaireTemplateScope(ctx, a.TenantID, QuestionnaireTemplateControlIDs(in.Questions)); err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		result = packagedomain.QuestionnaireTemplate{ID: s.config.IDs.NewID("qt"), TenantID: a.TenantID, Name: in.Name, Version: in.Version, Questions: in.Questions, SchemaVersion: packagedomain.QuestionnaireTemplateVersion, CreatedAt: now}
		if err := ValidateQuestionnaireTemplateRecord(result); err != nil {
			return err
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertQuestionnaireTemplate(ctx, cloneQuestionnaireTemplate(result)); err != nil {
			return err
		}
		if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "questionnaire_template.created", SubjectType: "questionnaire_template", SubjectID: result.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: now}); err != nil {
			return err
		}
		return contextError(ctx)
	})
	if err != nil {
		return packagedomain.QuestionnaireTemplate{}, err
	}
	return cloneQuestionnaireTemplate(result), nil
}

// The persistence boundary uses the same canonical rules and exact encoded
// byte budget. It must not silently normalize a forged record on insertion.
func ValidateQuestionnaireTemplateRecord(v packagedomain.QuestionnaireTemplate) error {
	if !summaryString(v.ID, MaxQuestionnaireTemplateTextBytes) || !summaryString(v.TenantID, MaxQuestionnaireTemplateTextBytes) || v.ID != strings.TrimSpace(v.ID) || v.TenantID != strings.TrimSpace(v.TenantID) || v.SchemaVersion != packagedomain.QuestionnaireTemplateVersion || v.CreatedAt.IsZero() || v.CreatedAt.Year() < 1 || v.CreatedAt.Year() > 9999 {
		return ErrValidation
	}
	in, err := NormalizeQuestionnaireTemplateInput(CreateQuestionnaireTemplateInput{Name: v.Name, Version: v.Version, Questions: v.Questions})
	if err != nil || v.Name != in.Name || v.Version != in.Version {
		return ErrValidation
	}
	for i, q := range v.Questions {
		n := in.Questions[i]
		if q.ID != n.ID || q.Prompt != n.Prompt || q.ControlID != n.ControlID || q.EvidenceType != n.EvidenceType || !slices.Equal(q.AllowedFields, n.AllowedFields) {
			return ErrValidation
		}
	}
	encoded, err := EncodeQuestionnaireTemplate(v)
	if err != nil || len(encoded) > MaxGeneratedReportBytes {
		return ErrValidation
	}
	return nil
}
func cloneQuestionnaireQuestions(qs []packagedomain.QuestionnaireQuestion) []packagedomain.QuestionnaireQuestion {
	out := append([]packagedomain.QuestionnaireQuestion(nil), qs...)
	for i := range out {
		out[i].AllowedFields = append([]string(nil), out[i].AllowedFields...)
	}
	return out
}
func cloneQuestionnaireTemplate(v packagedomain.QuestionnaireTemplate) packagedomain.QuestionnaireTemplate {
	v.Questions = cloneQuestionnaireQuestions(v.Questions)
	return v
}

func questionnaireQuestionsDocument(qs []packagedomain.QuestionnaireQuestion) []map[string]any {
	out := make([]map[string]any, len(qs))
	for i, q := range qs {
		out[i] = map[string]any{"id": q.ID, "prompt": q.Prompt}
		if q.EvidenceType != "" {
			out[i]["evidence_type"] = q.EvidenceType
		}
		if q.ControlID != "" {
			out[i]["control_id"] = q.ControlID
		}
		if len(q.AllowedFields) > 0 {
			out[i]["allowed_fields"] = q.AllowedFields
		}
	}
	return out
}
func EncodeQuestionnaireQuestions(qs []packagedomain.QuestionnaireQuestion) ([]byte, error) {
	return json.Marshal(questionnaireQuestionsDocument(qs))
}
func EncodeQuestionnaireTemplate(v packagedomain.QuestionnaireTemplate) ([]byte, error) {
	return json.Marshal(map[string]any{"id": v.ID, "tenant_id": v.TenantID, "name": v.Name, "version": v.Version, "questions": questionnaireQuestionsDocument(v.Questions), "schema_version": v.SchemaVersion, "created_at": v.CreatedAt})
}
