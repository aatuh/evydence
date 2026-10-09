package app

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Authorization joins the outer replay transaction and never checks duplicate
// keys, reads installed metadata, allocates IDs, consults a clock or writes.
func (s *ControlCommands) AuthorizeControlFrameworkCreation(ctx context.Context, a identitydomain.Actor, in CreateControlFrameworkInput) error {
	if err := s.preflight(ctx, a); err != nil {
		return err
	}
	if _, err := NormalizeControlFrameworkInput(in); err != nil || !validControlTenant(a.TenantID) {
		return ErrValidation
	}
	return s.config.Transactions.ExecuteControls(ctx, func(ctx context.Context, tx ControlTransaction) error {
		if err := tx.Authorize(ctx, a, controlAdminRequest()); err != nil {
			return err
		}
		return tx.LockControlCreationTenant(ctx, a.TenantID)
	})
}

func (s *ControlCommands) AuthorizeSecurityControlCreation(ctx context.Context, a identitydomain.Actor, in CreateSecurityControlInput) error {
	if err := s.preflight(ctx, a); err != nil {
		return err
	}
	in, err := NormalizeSecurityControlInput(in)
	if err != nil || !validControlTenant(a.TenantID) || len(a.TenantID)+len(in.FrameworkID)+len(in.Code) > 2048 {
		return ErrValidation
	}
	return s.config.Transactions.ExecuteControls(ctx, func(ctx context.Context, tx ControlTransaction) error {
		if err := tx.Authorize(ctx, a, controlAdminRequest()); err != nil {
			return err
		}
		if err := tx.LockControlCreationTenant(ctx, a.TenantID); err != nil {
			return err
		}
		exists, err := tx.ControlFrameworkExists(ctx, a.TenantID, in.FrameworkID)
		if err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		return nil
	})
}
