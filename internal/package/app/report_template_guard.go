package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const MaxReportTemplateTextBytes = 64 << 10
const MaxReportTemplateFields = 1024
const MaxReportTemplateKeyBytes = 2304

// ReportTemplateScopeLocker is implemented by flat runtime transactions. The
// legacy Service transaction bridge is not a native HTTP replay capability.
type ReportTemplateScopeLocker interface {
	LockReportTemplateTenant(context.Context, string) error
	LockReportTemplateIdentity(context.Context, string, string) error
}

func validReportTemplateText(s string, max int) bool {
	return len(s) <= max && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

func NormalizeReportTemplateCreation(in CreateReportTemplateInput) (CreateReportTemplateInput, error) {
	for _, v := range []string{in.Name, in.Version, in.ReportType} {
		if !validReportTemplateText(v, MaxReportTemplateTextBytes) {
			return CreateReportTemplateInput{}, ErrValidation
		}
	}
	if !validReportTemplateText(in.Template, int(ReportTemplateRequestLimit)) || len(in.AllowedFields) > MaxReportTemplateFields {
		return CreateReportTemplateInput{}, ErrValidation
	}
	for _, field := range in.AllowedFields {
		if !validReportTemplateText(field, MaxReportTemplateTextBytes) {
			return CreateReportTemplateInput{}, ErrValidation
		}
	}
	in.Name, in.Version, in.ReportType = strings.TrimSpace(in.Name), strings.TrimSpace(in.Version), strings.TrimSpace(in.ReportType)
	var err error
	in.AllowedFields, err = normalizedNonEmptyStrings(in.AllowedFields, true)
	if err != nil || in.Name == "" || in.Version == "" || in.ReportType == "" || len(in.AllowedFields) == 0 {
		return CreateReportTemplateInput{}, ErrValidation
	}
	in.Template = strings.TrimSpace(in.Template)
	return in, nil
}

func NormalizeReportRendering(in RenderReportInput) (RenderReportInput, error) {
	if !validReportTemplateText(in.TemplateID, 1024) || !validReportTemplateText(in.SubjectType, MaxReportTemplateTextBytes) || !validReportTemplateText(in.SubjectID, MaxReportTemplateTextBytes) || strings.TrimSpace(in.TemplateID) == "" || strings.TrimSpace(in.SubjectType) == "" || strings.TrimSpace(in.SubjectID) == "" {
		return RenderReportInput{}, ErrValidation
	}
	in.TemplateID = strings.TrimSpace(in.TemplateID)
	// Subject labels are intentionally not dereferenced. Preserve raw values in
	// output while the stored report coordinates retain their existing trimming.
	return in, nil
}

func validateReportTemplateTenant(a identitydomain.Actor) error {
	if a.TenantID == "" || !validReportTemplateText(a.TenantID, 1024) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	return nil
}

func (s *TemplateCommands) AuthorizeReportTemplateCreation(ctx context.Context, a identitydomain.Actor, in CreateReportTemplateInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateActor(a); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReportRead, ScopeOnly: true}); err != nil {
		return err
	}
	if err := validateReportTemplateTenant(a); err != nil {
		return err
	}
	var err error
	in, err = NormalizeReportTemplateCreation(in)
	if err != nil {
		return err
	}
	if len(a.TenantID)+len(in.Name)+len(in.Version) > MaxReportTemplateKeyBytes {
		return ErrValidation
	}
	return s.authorizeReportTemplateScope(ctx, a, "")
}

func (s *TemplateCommands) AuthorizeReportRendering(ctx context.Context, a identitydomain.Actor, in RenderReportInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateActor(a); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReportRead, ScopeOnly: true}); err != nil {
		return err
	}
	if err := validateReportTemplateTenant(a); err != nil {
		return err
	}
	var err error
	in, err = NormalizeReportRendering(in)
	if err != nil {
		return err
	}
	return s.authorizeReportTemplateScope(ctx, a, in.TemplateID)
}

func (s *TemplateCommands) authorizeReportTemplateScope(ctx context.Context, a identitydomain.Actor, id string) error {
	return s.config.Transactions.ExecuteReportTemplate(ctx, func(ctx context.Context, tx TemplateTransaction) error {
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReportRead, TenantWide: true}); err != nil {
			return err
		}
		guard, ok := tx.(ReportTemplateScopeLocker)
		if !ok {
			return ErrValidation
		}
		if err := guard.LockReportTemplateTenant(ctx, a.TenantID); err != nil {
			return err
		}
		if id != "" {
			return guard.LockReportTemplateIdentity(ctx, a.TenantID, id)
		}
		return nil
	})
}
