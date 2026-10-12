package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type customerAuditSnapshotPages struct{ tx pgx.Tx }

func (r customerAuditSnapshotPages) ReadAuditChainVerificationPage(ctx context.Context, view verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	return repositories.ReadAuditChainSnapshotPage(ctx, r.tx, view, after, budget)
}

// Canonical audit data is consumed only by Verification's read-only inspector.
// The public package receives the aggregate result, count and head, never audit
// subjects, actor identities, metadata, check details or signature/key records.
// Source inspection has its own 8 MiB bound; only the summary charges manifest
// bytes. The caller owns the same repeatable-read view as all other sections.
func readCustomerPackageAuditTx(ctx context.Context, tx pgx.Tx, tenant, product, release string, now time.Time, budget *customerSnapshotBudget, hasher verificationapp.CanonicalHasher, verifier verificationapp.PayloadSignatureVerifier) (map[string]any, error) {
	if err := validateCustomerSnapshotRead(ctx, tx, tenant, product, release, budget); err != nil {
		return nil, err
	}
	now = now.UTC()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9999 || hasher == nil || verifier == nil {
		return nil, packageapp.ErrValidation
	}
	if err := requireCustomerSnapshotScope(ctx, tx, tenant, product, release); err != nil {
		return nil, err
	}
	view, err := repositories.ReadAuditChainSnapshotView(ctx, tx, tenant)
	if err != nil {
		return nil, customerAuditSnapshotError(err)
	}
	inspection, err := verificationapp.InspectAuditChainSnapshot(ctx, customerAuditSnapshotPages{tx}, view, tenant, now, hasher, verifier)
	if err != nil {
		return nil, customerAuditSnapshotError(err)
	}
	result := "passed"
	for _, check := range inspection.Checks {
		if check.Result == "failed" {
			result = "failed"
			break
		}
	}
	out := map[string]any{"result": result, "latest_sequence": view.EntryCount, "head_hash": view.HeadHash, "checks": []map[string]any{{"name": "audit_chain_integrity", "result": result}}}
	body, err := json.Marshal(out)
	if err != nil || len(body) > budget.remainingBytes {
		return nil, packageapp.ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	budget.remainingBytes -= len(body)
	return out, nil
}

func customerAuditSnapshotError(err error) error {
	switch {
	case errors.Is(err, app.ErrNotFound), errors.Is(err, verificationapp.ErrNotFound):
		return packageapp.ErrNotFound
	case errors.Is(err, app.ErrValidation), errors.Is(err, verificationapp.ErrValidation):
		return packageapp.ErrValidation
	case errors.Is(err, app.ErrConflict), errors.Is(err, verificationapp.ErrConflict):
		return packageapp.ErrConflict
	default:
		return err
	}
}
