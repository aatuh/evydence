package query

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type ReleaseReadinessReader interface {
	ReadReleaseReadinessSnapshot(context.Context, string, string) (riskapp.ReadinessSnapshot, error)
}

// ReleaseReadinessQuery evaluates committed facts without persisting a policy
// receipt. Explicit policy-evaluation commands retain their write semantics.
type ReleaseReadinessQuery struct {
	reader ReleaseReadinessReader
	now    func() time.Time
}

func NewReleaseReadinessQuery(reader ReleaseReadinessReader, now func() time.Time) (*ReleaseReadinessQuery, error) {
	if reader == nil || now == nil {
		return nil, ErrValidation
	}
	return &ReleaseReadinessQuery{reader: reader, now: now}, nil
}

func (q *ReleaseReadinessQuery) Preview(ctx context.Context, actor identitydomain.Actor, releaseID string) (riskdomain.PolicyEvaluation, error) {
	var empty riskdomain.PolicyEvaluation
	if q == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	visibility, err := authz.ReadVisibility(ctx, actor, authz.ActionReleaseReadinessRead)
	if err != nil {
		return empty, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return empty, ErrValidation
	}
	tenantWide, products, releases := visibility.TenantWide, visibility.ProductIDs, visibility.ReleaseIDs
	if !tenantWide && !slices.Contains(releases, releaseID) && len(products) == 0 {
		return empty, application.ErrForbidden
	}
	snapshot, err := q.reader.ReadReleaseReadinessSnapshot(ctx, visibility.TenantID, releaseID)
	if err != nil {
		return empty, err
	}
	if snapshot.SnapshotVersion != riskapp.ReadinessSnapshotVersion || snapshot.TenantID != actor.TenantID || snapshot.ProductID == "" || snapshot.ReleaseID != releaseID || snapshot.PackageCount < 0 {
		return empty, ErrInvalidProjection
	}
	if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionReleaseReadinessRead, Resources: authz.ResourceReferences{TenantID: snapshot.TenantID, ProductID: snapshot.ProductID, ReleaseID: releaseID}}); err != nil {
		return empty, err
	}
	evaluation, err := riskapp.EvaluateReadinessSnapshot(snapshot, q.now().UTC())
	if err != nil {
		return empty, ErrInvalidProjection
	}
	return evaluation, nil
}
