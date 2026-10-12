package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var _ verificationapp.SigningOperationReader = futureExtensions{}

func (r futureExtensions) ReadSigningOperationProvider(ctx context.Context, tenant, id string) (verificationapp.SigningOperationProvider, error) {
	p := verificationapp.SigningOperationProvider{TenantID: tenant, ID: id}
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT left(type,129),left(status,129),left(key_ref,4097),octet_length(type)>128 OR octet_length(status)>128 OR octet_length(key_ref)>4096 FROM signing_providers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&p.Type, &p.Status, &p.KeyRef, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return verificationapp.SigningOperationProvider{}, app.ErrNotFound
	}
	if err != nil {
		return verificationapp.SigningOperationProvider{}, fmt.Errorf("read signing operation provider: %w", err)
	}
	if oversized {
		return verificationapp.SigningOperationProvider{}, app.ErrValidation
	}
	return p, nil
}
func (r futureExtensions) ReadSigningOperationScope(ctx context.Context, tenant, kind, id string) (verificationapp.SigningOperationScope, error) {
	s, err := r.ReadEvidenceSummaryScope(ctx, tenant, kind, id)
	return verificationapp.SigningOperationScope{TenantID: s.TenantID, SubjectType: s.SubjectType, SubjectID: s.SubjectID}, err
}
func (r futureExtensions) InsertFocusedSigningOperation(ctx context.Context, s verificationdomain.Signature, v verificationdomain.SigningOperation) error {
	if _, err := r.ReadSigningOperationScope(ctx, v.TenantID, v.SubjectType, v.SubjectID); err != nil {
		return err
	}
	p, err := r.ReadSigningOperationProvider(ctx, v.TenantID, v.ProviderID)
	if err != nil {
		return err
	}
	if err := verificationapp.ValidateSigningOperationProvider(p, v.TenantID, v.ProviderID); err != nil {
		return err
	}
	checks := make([]domain.VerifyCheck, len(v.Checks))
	for i, c := range v.Checks {
		checks[i] = domain.VerifyCheck{Name: c.Name, Result: c.Result, Detail: c.Detail}
	}
	return r.InsertSigningOperation(ctx, domain.Signature{ID: s.ID, TenantID: s.TenantID, SubjectType: s.SubjectType, SubjectID: s.SubjectID, KeyID: s.KeyID, Algorithm: s.Algorithm, Value: s.Value, CreatedAt: s.CreatedAt}, domain.SigningOperation{ID: v.ID, TenantID: v.TenantID, ProviderID: v.ProviderID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, PayloadHash: v.PayloadHash, CanonicalPayloadHash: v.CanonicalPayloadHash, RequestID: v.RequestID, ProviderRequestID: v.ProviderRequestID, SignatureRef: v.SignatureRef, Result: v.Result, Checks: checks, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}
