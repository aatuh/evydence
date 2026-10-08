package app

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func (r memoryFutureExtensionsRepository) ReadPDFReportScope(ctx context.Context, tenant, product, release string) (packageapp.PDFReportScope, error) {
	s, err := r.ReadGraphSnapshotScope(ctx, tenant, product, release)
	return packageapp.PDFReportScope{TenantID: s.TenantID, Resources: s.Resources}, err
}
func (r memoryFutureExtensionsRepository) ReadSigningOperationScope(ctx context.Context, tenant, kind, id string) (verificationapp.SigningOperationScope, error) {
	s, err := r.ReadEvidenceSummaryScope(ctx, tenant, kind, id)
	return verificationapp.SigningOperationScope{TenantID: s.TenantID, SubjectType: s.SubjectType, SubjectID: s.SubjectID}, err
}
func (r memoryFutureExtensionsRepository) ReadSigningOperationProvider(ctx context.Context, tenant, id string) (verificationapp.SigningOperationProvider, error) {
	var out verificationapp.SigningOperationProvider
	if !memoryMembershipQueryText(id, verificationapp.MaxSigningOperationIDBytes) {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		p, ok := state.SigningProviders[id]
		if !ok || p.ID != id || p.TenantID != tenant {
			return ErrNotFound
		}
		if !memoryMembershipText(p.Type, 128) || !memoryMembershipText(p.Status, 128) || !memoryMembershipText(p.KeyRef, 4096) {
			return ErrValidation
		}
		out = verificationapp.SigningOperationProvider{ID: p.ID, TenantID: p.TenantID, Type: p.Type, Status: p.Status, KeyRef: p.KeyRef}
		return nil
	})
	if err != nil {
		return verificationapp.SigningOperationProvider{}, err
	}
	return out, nil
}
func (r memoryFutureExtensionsRepository) InsertFocusedPDFReportPackage(ctx context.Context, v packagedomain.PDFReportPackage) error {
	if !memoryMembershipQueryText(v.ID, 1024) || v.SchemaVersion != packagedomain.PDFReportPackageVersion || v.CreatedAt.IsZero() || v.CreatedAt.Year() < 1 || v.CreatedAt.Year() > 9999 || !memoryExperimentalLimitations(v.Limitations) || !memoryMembershipText(v.PayloadRef, 4096) {
		return ErrValidation
	}
	in, err := packageapp.NormalizePDFReportInput(packageapp.CreatePDFReportInput{ReportType: v.ReportType, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Title: v.Title})
	if err != nil || in.ReportType != v.ReportType || in.ProductID != v.ProductID || in.ReleaseID != v.ReleaseID || in.Title != v.Title {
		return ErrValidation
	}
	if _, err := r.ReadPDFReportScope(ctx, v.TenantID, v.ProductID, v.ReleaseID); err != nil {
		return err
	}
	raw, err := packageapp.PDFReportPayload(in)
	if err != nil || BytesPayloadSource(raw).Digest != v.PayloadHash || int64(len(raw)) != v.PayloadSize {
		return ErrValidation
	}
	if v.PayloadRef != "" {
		_, key, err := CanonicalObjectPayloadKeys(v.TenantID, v.PayloadHash)
		if err != nil || v.PayloadRef != "object://"+key {
			return ErrValidation
		}
	}
	return r.InsertPDFReportPackage(ctx, domain.PDFReportPackage{ID: v.ID, TenantID: v.TenantID, ReportType: v.ReportType, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Title: v.Title, PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, PayloadSize: v.PayloadSize, Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}
func (r memoryFutureExtensionsRepository) InsertFocusedSigningOperation(ctx context.Context, s verificationdomain.Signature, v verificationdomain.SigningOperation) error {
	if !memoryMembershipQueryText(v.ID, 1024) || !memoryMembershipQueryText(s.ID, 1024) || v.SchemaVersion != verificationdomain.SigningOperationVersion || v.CreatedAt.IsZero() || v.CreatedAt.Year() < 1 || v.CreatedAt.Year() > 9999 || s.TenantID != v.TenantID || s.SubjectType != v.SubjectType || s.SubjectID != v.SubjectID || s.KeyID != v.ProviderID || s.ID != v.SignatureRef || !s.CreatedAt.Equal(v.CreatedAt) || v.Result != "passed" || len(v.Checks) > verificationapp.MaxSigningOperationChecks+4 {
		return ErrValidation
	}
	in, err := verificationapp.NormalizeSigningOperationInput(verificationapp.SigningOperationInput{ProviderID: v.ProviderID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, PayloadHash: v.PayloadHash})
	if err != nil || in.ProviderID != v.ProviderID || in.SubjectType != v.SubjectType || in.SubjectID != v.SubjectID || in.PayloadHash != v.PayloadHash {
		return ErrValidation
	}
	if _, err := verificationapp.NormalizeSigningOperationInput(verificationapp.SigningOperationInput{ProviderID: v.ProviderID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, PayloadHash: v.CanonicalPayloadHash}); err != nil {
		return ErrValidation
	}
	if !memoryMembershipQueryText(v.RequestID, 1024) || !memoryMembershipText(v.ProviderRequestID, 1024) || !memoryMembershipQueryText(s.Algorithm, 128) || !memoryMembershipQueryText(s.Value, 32768) {
		return ErrValidation
	}
	for _, c := range v.Checks {
		if !memoryMembershipText(c.Name, 128) || !memoryMembershipText(c.Detail, 4096) || c.Result != "passed" && c.Result != "skipped" {
			return ErrValidation
		}
	}
	if _, err := r.ReadSigningOperationScope(ctx, v.TenantID, v.SubjectType, v.SubjectID); err != nil {
		return err
	}
	p, err := r.ReadSigningOperationProvider(ctx, v.TenantID, v.ProviderID)
	if err != nil {
		return err
	}
	if err := verificationapp.ValidateSigningOperationProvider(p, v.TenantID, v.ProviderID); err != nil {
		return mapSigningOperationContextError(err)
	}
	checks := make([]domain.VerifyCheck, len(v.Checks))
	for i, c := range v.Checks {
		checks[i] = domain.VerifyCheck{Name: c.Name, Result: c.Result, Detail: c.Detail}
	}
	return r.InsertSigningOperation(ctx, domain.Signature{ID: s.ID, TenantID: s.TenantID, SubjectType: s.SubjectType, SubjectID: s.SubjectID, KeyID: s.KeyID, Algorithm: s.Algorithm, Value: s.Value, CreatedAt: s.CreatedAt}, domain.SigningOperation{ID: v.ID, TenantID: v.TenantID, ProviderID: v.ProviderID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, PayloadHash: v.PayloadHash, CanonicalPayloadHash: v.CanonicalPayloadHash, RequestID: v.RequestID, ProviderRequestID: v.ProviderRequestID, SignatureRef: v.SignatureRef, Result: v.Result, Checks: checks, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}

var _ packageapp.PDFReportReader = memoryFutureExtensionsRepository{}
var _ verificationapp.SigningOperationReader = memoryFutureExtensionsRepository{}
