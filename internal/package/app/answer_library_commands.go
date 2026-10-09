package app

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const (
	MaxAnswerLibraryIDBytes       = 1024
	MaxAnswerLibraryTextBytes     = 64 << 10
	MaxAnswerLibraryEvidenceIDs   = 4096
	MaxAnswerLibraryLimitations   = 128
	AnswerLibraryReviewLimitation = "Answer library entries are reusable drafts and require human review before external use."
)

type CreateAnswerLibraryEntryInput struct {
	QuestionID, EvidenceType, ControlID, ProductID, ReleaseID, Answer string
	EvidenceIDs, Limitations                                          []string
}

// ProductID/ReleaseID retain raw selection and response semantics. Resources
// contain current, resolved ownership coordinates used only for authorization.
type AnswerLibraryScope struct {
	TenantID, ProductID, ReleaseID string
	Resources                      application.ResourceReferences
}
type AnswerLibraryReader interface {
	ReadAnswerLibraryScope(context.Context, string, string, string) (AnswerLibraryScope, error)
	ValidateAnswerLibraryReferences(context.Context, AnswerLibraryScope, string, []string) error
}

// These ports cannot read existing private answers or raw evidence payloads.
type AnswerLibraryTransaction interface {
	AnswerLibraryReader
	InsertAnswerLibraryEntry(context.Context, packagedomain.QuestionnaireAnswerLibraryEntry) error
	application.Authorizer
	application.AuditAppender
}
type AnswerLibraryTransactions interface {
	ExecuteAnswerLibrary(context.Context, string, func(context.Context, AnswerLibraryTransaction) error) error
}
type AnswerLibraryCommandConfig struct {
	Transactions AnswerLibraryTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type AnswerLibraryCommands struct{ config AnswerLibraryCommandConfig }

func NewAnswerLibraryCommands(c AnswerLibraryCommandConfig) (*AnswerLibraryCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &AnswerLibraryCommands{c}, nil
}

// Bounds apply before normalization/copying. Duplicate citations/limitations
// and blank limitations preserve the existing inert metadata contract.
func NormalizeAnswerLibraryInput(in CreateAnswerLibraryEntryInput) (CreateAnswerLibraryEntryInput, error) {
	if len(in.EvidenceIDs) > MaxAnswerLibraryEvidenceIDs || len(in.Limitations) > MaxAnswerLibraryLimitations {
		return in, ErrValidation
	}
	total := 0
	for _, v := range []string{in.QuestionID, in.EvidenceType, in.ControlID, in.ProductID, in.ReleaseID} {
		if !questionnaireTemplateText(v, MaxAnswerLibraryIDBytes) {
			return in, ErrValidation
		}
		total += len(v)
	}
	if !questionnaireTemplateText(in.Answer, MaxAnswerLibraryTextBytes) {
		return in, ErrValidation
	}
	total += len(in.Answer)
	for _, v := range in.EvidenceIDs {
		if !summaryString(v, MaxAnswerLibraryIDBytes) {
			return in, ErrValidation
		}
		total += len(v)
	}
	for _, v := range in.Limitations {
		if !questionnaireTemplateText(v, MaxAnswerLibraryTextBytes) {
			return in, ErrValidation
		}
		total += len(v)
	}
	if total > MaxGeneratedReportBytes {
		return in, ErrValidation
	}
	in.QuestionID, in.EvidenceType, in.ControlID = strings.TrimSpace(in.QuestionID), strings.TrimSpace(in.EvidenceType), strings.TrimSpace(in.ControlID)
	in.ProductID, in.ReleaseID, in.Answer = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.Answer)
	if in.Answer == "" || in.QuestionID == "" && in.EvidenceType == "" && in.ControlID == "" {
		return in, ErrValidation
	}
	in.EvidenceIDs = append([]string(nil), in.EvidenceIDs...)
	for i := range in.EvidenceIDs {
		in.EvidenceIDs[i] = strings.TrimSpace(in.EvidenceIDs[i])
	}
	sort.Strings(in.EvidenceIDs)
	in.Limitations = append([]string(nil), in.Limitations...)
	for i := range in.Limitations {
		in.Limitations[i] = strings.TrimSpace(in.Limitations[i])
	}
	sort.Strings(in.Limitations)
	if len(in.Limitations) == 0 {
		in.Limitations = []string{AnswerLibraryReviewLimitation}
	}
	return in, nil
}
func (s *AnswerLibraryCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateAnswerLibraryEntryInput) (CreateAnswerLibraryEntryInput, error) {
	if s == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, ScopeOnly: true}); err != nil {
		return in, err
	}
	return NormalizeAnswerLibraryInput(in)
}
func (s *AnswerLibraryCommands) authorize(ctx context.Context, tx AnswerLibraryTransaction, a identitydomain.Actor, in CreateAnswerLibraryEntryInput) error {
	scope, err := tx.ReadAnswerLibraryScope(ctx, a.TenantID, in.ProductID, in.ReleaseID)
	if err != nil {
		return err
	}
	r := scope.Resources
	if scope.TenantID != a.TenantID || scope.ProductID != in.ProductID || scope.ReleaseID != in.ReleaseID || r != (application.ResourceReferences{ProductID: r.ProductID, ReleaseID: r.ReleaseID}) || r.ReleaseID != in.ReleaseID || in.ProductID != "" && r.ProductID != in.ProductID || in.ReleaseID != "" && !summaryString(r.ProductID, MaxAnswerLibraryIDBytes) || in.ProductID == "" && in.ReleaseID == "" && r != (application.ResourceReferences{}) {
		return ErrNotFound
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: r, TenantWide: r == (application.ResourceReferences{})}); err != nil {
		return err
	}
	return tx.ValidateAnswerLibraryReferences(ctx, scope, in.ControlID, in.EvidenceIDs)
}

// Same-key replay rechecks current root grants and all referenced ownership,
// without loading answer text or publishing new answer/audit effects.
func (s *AnswerLibraryCommands) AuthorizeCreateAnswerLibraryEntry(ctx context.Context, a identitydomain.Actor, in CreateAnswerLibraryEntryInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteAnswerLibrary(ctx, a.TenantID, func(ctx context.Context, tx AnswerLibraryTransaction) error {
		if err := s.authorize(ctx, tx, a, in); err != nil {
			return err
		}
		return contextError(ctx)
	})
}
func (s *AnswerLibraryCommands) CreateAnswerLibraryEntry(ctx context.Context, a identitydomain.Actor, in CreateAnswerLibraryEntryInput) (packagedomain.QuestionnaireAnswerLibraryEntry, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return packagedomain.QuestionnaireAnswerLibraryEntry{}, err
	}
	var v packagedomain.QuestionnaireAnswerLibraryEntry
	err = s.config.Transactions.ExecuteAnswerLibrary(ctx, a.TenantID, func(ctx context.Context, tx AnswerLibraryTransaction) error {
		if err := s.authorize(ctx, tx, a, in); err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		v = packagedomain.QuestionnaireAnswerLibraryEntry{ID: s.config.IDs.NewID("qal"), TenantID: a.TenantID, QuestionID: in.QuestionID, EvidenceType: in.EvidenceType, ControlID: in.ControlID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Answer: in.Answer, EvidenceIDs: in.EvidenceIDs, Limitations: in.Limitations, SchemaVersion: packagedomain.QuestionnaireAnswerLibraryVersion, CreatedAt: now}
		if err := ValidateAnswerLibraryRecord(v); err != nil {
			return err
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertAnswerLibraryEntry(ctx, cloneAnswerLibraryEntry(v)); err != nil {
			return err
		}
		if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "questionnaire_answer_library.created", SubjectType: "questionnaire_answer_library", SubjectID: v.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: now}); err != nil {
			return err
		}
		return contextError(ctx)
	})
	if err != nil {
		return packagedomain.QuestionnaireAnswerLibraryEntry{}, err
	}
	return cloneAnswerLibraryEntry(v), nil
}
func ValidateAnswerLibraryRecord(v packagedomain.QuestionnaireAnswerLibraryEntry) error {
	if !summaryString(v.ID, MaxAnswerLibraryIDBytes) || !summaryString(v.TenantID, MaxAnswerLibraryIDBytes) || v.ID != strings.TrimSpace(v.ID) || v.TenantID != strings.TrimSpace(v.TenantID) || v.SchemaVersion != packagedomain.QuestionnaireAnswerLibraryVersion || v.CreatedAt.IsZero() || v.CreatedAt.Year() < 1 || v.CreatedAt.Year() > 9999 {
		return ErrValidation
	}
	in, err := NormalizeAnswerLibraryInput(CreateAnswerLibraryEntryInput{QuestionID: v.QuestionID, EvidenceType: v.EvidenceType, ControlID: v.ControlID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Answer: v.Answer, EvidenceIDs: v.EvidenceIDs, Limitations: v.Limitations})
	if err != nil || in.QuestionID != v.QuestionID || in.EvidenceType != v.EvidenceType || in.ControlID != v.ControlID || in.ProductID != v.ProductID || in.ReleaseID != v.ReleaseID || in.Answer != v.Answer || !slices.Equal(in.EvidenceIDs, v.EvidenceIDs) || !slices.Equal(in.Limitations, v.Limitations) {
		return ErrValidation
	}
	raw, err := EncodeAnswerLibraryEntry(v)
	if err != nil || len(raw) > MaxGeneratedReportBytes {
		return ErrValidation
	}
	return nil
}
func cloneAnswerLibraryEntry(v packagedomain.QuestionnaireAnswerLibraryEntry) packagedomain.QuestionnaireAnswerLibraryEntry {
	v.EvidenceIDs = append([]string(nil), v.EvidenceIDs...)
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}
func EncodeAnswerLibraryEntry(v packagedomain.QuestionnaireAnswerLibraryEntry) ([]byte, error) {
	doc := map[string]any{"id": v.ID, "tenant_id": v.TenantID, "answer": v.Answer, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt}
	for k, value := range map[string]string{"question_id": v.QuestionID, "evidence_type": v.EvidenceType, "control_id": v.ControlID, "product_id": v.ProductID, "release_id": v.ReleaseID} {
		if value != "" {
			doc[k] = value
		}
	}
	if len(v.EvidenceIDs) > 0 {
		doc["evidence_ids"] = v.EvidenceIDs
	}
	if len(v.Limitations) > 0 {
		doc["limitations"] = v.Limitations
	}
	return json.Marshal(doc)
}
