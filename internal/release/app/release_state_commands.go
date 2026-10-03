package app

import (
	"context"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ReleaseStateReader resolves current tenant-owned parent coordinates before
// authorization. The transaction locks and rechecks the release before write.
type ReleaseStateReader interface {
	ProductCoordinateReader
	ReadReleaseState(context.Context, string, string) (releasedomain.Release, error)
}

type ReleaseStateTransaction interface {
	ReleaseStateReader
	application.Authorizer
	UpdateRelease(context.Context, releasedomain.Release, int64, string) error
	AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error)
}

type ReleaseStateTransactionRunner interface {
	ExecuteReleaseState(context.Context, func(context.Context, ReleaseStateTransaction) error) error
}

type ReleaseStateCommandConfig struct {
	Reader       ReleaseStateReader
	Authorizer   application.Authorizer
	Transactions ReleaseStateTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}

type ReleaseStateCommands struct {
	reader       ReleaseStateReader
	authorizer   application.Authorizer
	transactions ReleaseStateTransactionRunner
	clock        application.Clock
	ids          application.IDGenerator
}

func NewReleaseStateCommands(config ReleaseStateCommandConfig) (*ReleaseStateCommands, error) {
	if config.Reader == nil || config.Authorizer == nil || config.Transactions == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &ReleaseStateCommands{
		reader: config.Reader, authorizer: config.Authorizer, transactions: config.Transactions,
		clock: config.Clock, ids: config.IDs,
	}, nil
}

func (s *ReleaseStateCommands) FreezeRelease(ctx context.Context, actor identitydomain.Actor, id string, expectedRevision int64) (releasedomain.Release, error) {
	return s.transitionRelease(ctx, actor, id, expectedRevision, releasedomain.ReleaseStateDraftValue, "release.frozen", releasedomain.Release.Freeze)
}

func (s *ReleaseStateCommands) ApproveRelease(ctx context.Context, actor identitydomain.Actor, id string, expectedRevision int64) (releasedomain.Release, error) {
	return s.transitionRelease(ctx, actor, id, expectedRevision, releasedomain.ReleaseStateFrozenValue, "release.approved", releasedomain.Release.Approve)
}

func (s *ReleaseStateCommands) transitionRelease(ctx context.Context, actor identitydomain.Actor, id string, expectedRevision int64, expectedState, eventType string, transition func(releasedomain.Release, time.Time) (releasedomain.Release, error)) (releasedomain.Release, error) {
	if s == nil {
		return releasedomain.Release{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return releasedomain.Release{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return releasedomain.Release{}, err
	}
	if expectedRevision < 1 {
		return releasedomain.Release{}, ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.Release{}, ErrNotFound
	}
	release, err := s.reader.ReadReleaseState(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if !releaseBelongsToTenant(release, actor.TenantID, id) || strings.TrimSpace(release.ProductID) == "" {
		return releasedomain.Release{}, ErrNotFound
	}
	product, err := s.reader.ReadProductCoordinates(ctx, actor.TenantID, release.ProductID)
	if err != nil {
		return releasedomain.Release{}, err
	}
	if product.ID != release.ProductID || product.TenantID != actor.TenantID {
		return releasedomain.Release{}, ErrNotFound
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{
		Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID},
	}); err != nil {
		return releasedomain.Release{}, err
	}
	if release.Revision != expectedRevision {
		return releasedomain.Release{}, NewVersionConflict(release.Revision)
	}
	if release.State.String() != expectedState {
		return releasedomain.Release{}, ErrConflict
	}
	transitionedAt := s.clock.Now().UTC()
	var updated releasedomain.Release
	err = s.transactions.ExecuteReleaseState(ctx, func(ctx context.Context, tx ReleaseStateTransaction) error {
		current, err := tx.ReadReleaseState(ctx, actor.TenantID, release.ID)
		if err != nil {
			return err
		}
		if !releaseBelongsToTenant(current, actor.TenantID, release.ID) {
			return ErrNotFound
		}
		if !sameReleaseCoordinates(current, release) {
			return ErrConflict
		}
		currentProduct, err := tx.ReadProductCoordinates(ctx, actor.TenantID, current.ProductID)
		if err != nil {
			return err
		}
		if currentProduct.ID != current.ProductID || currentProduct.TenantID != actor.TenantID {
			return ErrNotFound
		}
		if currentProduct != product {
			return ErrConflict
		}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{
			Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: current.ProductID, ReleaseID: current.ID},
		}); err != nil {
			return err
		}
		if current.Revision != expectedRevision {
			return NewVersionConflict(current.Revision)
		}
		if current.State.String() != expectedState {
			return ErrConflict
		}
		updated, err = transition(current, transitionedAt)
		if err != nil {
			return ErrConflict
		}
		if err := tx.UpdateRelease(ctx, updated, expectedRevision, expectedState); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, auditEventFor(s.ids, actor, transitionedAt, eventType, "release", updated.ID, ""))
		return err
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return updated, nil
}

type releaseStateTransactions struct{ runner TransactionRunner }

func (r releaseStateTransactions) ExecuteReleaseState(ctx context.Context, command func(context.Context, ReleaseStateTransaction) error) error {
	return r.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return command(ctx, releaseStateTransaction{tx: tx})
	})
}

type releaseStateTransaction struct{ tx Transaction }

func (t releaseStateTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return t.tx.Authorization().Authorize(ctx, actor, request)
}

func (t releaseStateTransaction) ReadReleaseState(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	return t.tx.Catalog().GetRelease(ctx, tenantID, id)
}

func (t releaseStateTransaction) ReadProductCoordinates(ctx context.Context, tenantID, id string) (ProductCoordinates, error) {
	return (legacyProductCoordinates{source: t.tx.Catalog()}).ReadProductCoordinates(ctx, tenantID, id)
}

// Full-model reads are confined to the explicit legacy/local service bridge.
type legacyReleaseStateReader struct{ source Reader }

func (r legacyReleaseStateReader) ReadReleaseState(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	return r.source.GetRelease(ctx, tenantID, id)
}

func (r legacyReleaseStateReader) ReadProductCoordinates(ctx context.Context, tenantID, id string) (ProductCoordinates, error) {
	return (legacyProductCoordinates{source: r.source}).ReadProductCoordinates(ctx, tenantID, id)
}

func (t releaseStateTransaction) UpdateRelease(ctx context.Context, release releasedomain.Release, expectedRevision int64, _ string) error {
	return t.tx.Catalog().UpdateRelease(ctx, release, expectedRevision)
}

func (t releaseStateTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, event)
}
