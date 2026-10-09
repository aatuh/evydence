package query

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
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
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return empty, application.ErrUnauthorized
	}
	if !actor.HasScope("verify:read") && !actor.HasScope("admin") {
		return empty, application.ErrForbidden
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return empty, ErrValidation
	}
	tenantWide, products, releases := decisionVisibility(actor, "verify:read")
	if !tenantWide && !decisionAllowed(false, products, releases, "", releaseID) && len(products) == 0 {
		return empty, application.ErrForbidden
	}
	snapshot, err := q.reader.ReadReleaseReadinessSnapshot(ctx, actor.TenantID, releaseID)
	if err != nil {
		return empty, err
	}
	if snapshot.SnapshotVersion != riskapp.ReadinessSnapshotVersion || snapshot.TenantID != actor.TenantID || snapshot.ProductID == "" || snapshot.ReleaseID != releaseID || snapshot.PackageCount < 0 {
		return empty, ErrInvalidProjection
	}
	if !decisionAllowed(tenantWide, products, releases, snapshot.ProductID, releaseID) {
		return empty, application.ErrForbidden
	}
	evaluation, err := riskapp.EvaluateReadinessSnapshot(snapshot, q.now().UTC())
	if err != nil {
		return empty, ErrInvalidProjection
	}
	return evaluation, nil
}
