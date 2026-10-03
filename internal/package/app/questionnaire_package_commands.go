package app

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type CreateQuestionnairePackageInput struct{ TemplateID, PackageID, ProductID, ReleaseID string }

// Selection retains the raw evidence filters. PackageResources describes an
// independently authorized association; it never supplies selection filters.
type QuestionnairePackageScope struct {
	Selection        QuestionnaireDraftScope
	PackageID        string
	PackageResources application.ResourceReferences
}
type QuestionnairePackageReader interface {
	ReadQuestionnairePackageScope(context.Context, string, CreateQuestionnairePackageInput) (QuestionnairePackageScope, error)
}
type QuestionnairePackageTransaction interface {
	QuestionnairePackageReader
	QuestionnaireResponseReader
	InsertQuestionnairePackage(context.Context, packagedomain.QuestionnairePackage) error
	application.Authorizer
	application.AuditAppender
}
type QuestionnairePackageTransactions interface {
	ExecuteQuestionnairePackage(context.Context, string, func(context.Context, QuestionnairePackageTransaction) error) error
}
type QuestionnairePackageCommandConfig struct {
	Transactions QuestionnairePackageTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type QuestionnairePackageCommands struct {
	config QuestionnairePackageCommandConfig
}

func NewQuestionnairePackageCommands(c QuestionnairePackageCommandConfig) (*QuestionnairePackageCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &QuestionnairePackageCommands{c}, nil
}
func NormalizeQuestionnairePackageInput(in CreateQuestionnairePackageInput) (CreateQuestionnairePackageInput, error) {
	d, err := NormalizeQuestionnaireDraftInput(CreateQuestionnaireDraftInput{TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	if err != nil || !draftText(in.PackageID, MaxQuestionnaireDraftIDBytes, false) {
		return in, ErrValidation
	}
	in.TemplateID, in.ProductID, in.ReleaseID = d.TemplateID, d.ProductID, d.ReleaseID
	in.PackageID = strings.TrimSpace(in.PackageID)
	return in, nil
}
func (s *QuestionnairePackageCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateQuestionnairePackageInput) (CreateQuestionnairePackageInput, error) {
	if s == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	in, err := NormalizeQuestionnairePackageInput(in)
	if err != nil {
		return in, err
	}
	return in, s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, ScopeOnly: true})
}

// ValidateQuestionnairePackageScope is shared by command and persistence
// adapters. Resolved parents cannot substitute for the submitted raw filters.
func ValidateQuestionnairePackageScope(tenant string, in CreateQuestionnairePackageInput, s QuestionnairePackageScope) error {
	d := s.Selection
	if d.TenantID != tenant || d.TemplateID != in.TemplateID || d.ProductID != in.ProductID || d.ReleaseID != in.ReleaseID {
		return ErrNotFound
	}
	refs := d.Resources
	for _, id := range []string{refs.ProductID, refs.ReleaseID, s.PackageResources.ProductID, s.PackageResources.ReleaseID, s.PackageResources.CustomerPackageID} {
		if !draftText(id, MaxQuestionnaireDraftIDBytes, false) || id != strings.TrimSpace(id) {
			return ErrConflict
		}
	}
	if refs != (application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID}) || refs.ReleaseID != in.ReleaseID || in.ProductID != "" && refs.ProductID != in.ProductID || refs.ReleaseID != "" && refs.ProductID == "" || in.ProductID == "" && in.ReleaseID == "" && refs.ProductID != "" {
		return ErrConflict
	}
	if in.PackageID == "" {
		if s.PackageID != "" || s.PackageResources != (application.ResourceReferences{}) {
			return ErrConflict
		}
		return nil
	}
	if s.PackageID != in.PackageID {
		return ErrNotFound
	}
	p := s.PackageResources
	if p.CustomerPackageID != in.PackageID || p.ProductID == "" || p != (application.ResourceReferences{ProductID: p.ProductID, ReleaseID: p.ReleaseID, CustomerPackageID: in.PackageID}) || refs.ProductID != "" && refs.ProductID != p.ProductID || in.ReleaseID != "" && in.ReleaseID != p.ReleaseID {
		return ErrConflict
	}
	return nil
}
func readAuthorizedQuestionnairePackageScope(ctx context.Context, tx QuestionnairePackageTransaction, a identitydomain.Actor, in CreateQuestionnairePackageInput) (QuestionnairePackageScope, error) {
	s, err := tx.ReadQuestionnairePackageScope(ctx, a.TenantID, in)
	if err != nil {
		return s, err
	}
	if err := ValidateQuestionnairePackageScope(a.TenantID, in, s); err != nil {
		return s, err
	}
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: s.Selection.Resources, TenantWide: s.Selection.Resources == (application.ResourceReferences{})}); err != nil {
		return s, err
	}
	if in.PackageID != "" {
		return s, tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: s.PackageResources})
	}
	return s, nil
}
func (s *QuestionnairePackageCommands) AuthorizeCreateQuestionnairePackage(ctx context.Context, a identitydomain.Actor, in CreateQuestionnairePackageInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteQuestionnairePackage(ctx, a.TenantID, func(ctx context.Context, tx QuestionnairePackageTransaction) error {
		_, err := readAuthorizedQuestionnairePackageScope(ctx, tx, a, in)
		return err
	})
}
func (s *QuestionnairePackageCommands) CreateQuestionnairePackage(ctx context.Context, a identitydomain.Actor, in CreateQuestionnairePackageInput) (packagedomain.QuestionnairePackage, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return packagedomain.QuestionnairePackage{}, err
	}
	var v packagedomain.QuestionnairePackage
	err = s.config.Transactions.ExecuteQuestionnairePackage(ctx, a.TenantID, func(ctx context.Context, tx QuestionnairePackageTransaction) error {
		scope, err := readAuthorizedQuestionnairePackageScope(ctx, tx, a, in)
		if err != nil {
			return err
		}
		responses, hash, err := assembleQuestionnaireResponses(ctx, tx, a, scope.Selection, ScopePackageWrite)
		if err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC()
		v = packagedomain.QuestionnairePackage{ID: s.config.IDs.NewID("qp"), TenantID: a.TenantID, TemplateID: in.TemplateID, PackageID: in.PackageID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Responses: responses, ManifestHash: hash, SchemaVersion: packagedomain.QuestionnairePackageVersion, CreatedAt: now}
		if err := ValidateQuestionnairePackageRecord(v); err != nil {
			return err
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertQuestionnairePackage(ctx, cloneQuestionnairePackage(v)); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "questionnaire_package.generated", SubjectType: "questionnaire_package", SubjectID: v.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: now, PayloadHash: hash})
		if err != nil {
			return err
		}
		return contextError(ctx)
	})
	if err != nil {
		return packagedomain.QuestionnairePackage{}, err
	}
	return cloneQuestionnairePackage(v), nil
}
func cloneQuestionnairePackage(v packagedomain.QuestionnairePackage) packagedomain.QuestionnairePackage {
	v.Responses = append([]packagedomain.QuestionnaireResponse(nil), v.Responses...)
	for i := range v.Responses {
		v.Responses[i].EvidenceIDs = append([]string(nil), v.Responses[i].EvidenceIDs...)
		v.Responses[i].Limitations = append([]string(nil), v.Responses[i].Limitations...)
	}
	return v
}
func ValidateQuestionnairePackageRecord(v packagedomain.QuestionnairePackage) error {
	for _, id := range []string{v.ID, v.TenantID, v.TemplateID} {
		if !draftText(id, MaxQuestionnaireDraftIDBytes, true) {
			return ErrValidation
		}
	}
	if _, err := NormalizeQuestionnairePackageInput(CreateQuestionnairePackageInput{TemplateID: v.TemplateID, PackageID: v.PackageID, ProductID: v.ProductID, ReleaseID: v.ReleaseID}); err != nil {
		return err
	}
	if v.SchemaVersion != packagedomain.QuestionnairePackageVersion || v.CreatedAt.IsZero() || v.CreatedAt.Year() < 1 || v.CreatedAt.Year() > 9999 {
		return ErrValidation
	}
	if err := validateQuestionnaireResponses(v.Responses, v.ManifestHash); err != nil {
		return err
	}
	encoded, err := EncodeQuestionnairePackage(v)
	if err != nil {
		return err
	}
	if len(encoded) > MaxGeneratedReportBytes {
		return ErrValidation
	}
	return nil
}
func EncodeQuestionnairePackage(v packagedomain.QuestionnairePackage) ([]byte, error) {
	responses := make([]map[string]any, len(v.Responses))
	for i, r := range v.Responses {
		responses[i] = questionnaireResponseDocument(r)
	}
	out := map[string]any{"id": v.ID, "tenant_id": v.TenantID, "template_id": v.TemplateID, "responses": responses, "manifest_hash": v.ManifestHash, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt}
	if v.PackageID != "" {
		out["package_id"] = v.PackageID
	}
	if v.ProductID != "" {
		out["product_id"] = v.ProductID
	}
	if v.ReleaseID != "" {
		out["release_id"] = v.ReleaseID
	}
	return json.Marshal(out)
}
