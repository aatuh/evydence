package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type verificationReceiptTransaction interface {
	application.AuditAppender
	application.OutboxEnqueuer
	InsertVerificationResult(context.Context, verificationdomain.VerificationResult) error
}

// persistVerificationReceipt shares policy aggregation and atomic receipt
// effects across focused subject commands. Authorization/inspection are done
// by the owning command before calling this transaction-scoped helper.
func persistVerificationReceipt(ctx context.Context, tx verificationReceiptTransaction, actor identitydomain.Actor, subject SubjectReference, inspection SubjectInspection, now time.Time, ids application.IDGenerator) (verificationdomain.VerificationResult, error) {
	inspection = cloneSubjectInspection(inspection)
	inspection.Profile = verificationdomain.NormalizeVerificationProfile(inspection.Profile)
	if !validInspection(inspection) {
		return verificationdomain.VerificationResult{}, ErrValidation
	}
	state := verificationdomain.AggregateVerificationState(inspection.Profile, inspection.Checks)
	if !inspection.StateOverride.IsZero() {
		if !validConservativeStateOverride(inspection, state) {
			return verificationdomain.VerificationResult{}, ErrValidation
		}
		state = inspection.StateOverride
	}
	result := verificationdomain.VerificationResult{ID: ids.NewID("vr"), TenantID: actor.TenantID, SubjectType: subject.Type, SubjectID: subject.ID, Result: state, Checks: inspection.Checks, Profile: inspection.Profile, Limitations: append([]string(nil), inspection.Profile.Limitations...), SchemaVersion: verificationdomain.VerificationResultSchemaVersion, VerifiedAt: now}
	if err := tx.InsertVerificationResult(ctx, result); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: ids.NewID("ace"), TenantID: actor.TenantID, EntryType: "subject.verified", SubjectType: "verification_result", SubjectID: result.ID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: now}); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := tx.EnqueueOutbox(ctx, application.OutboxEvent{ID: ids.NewID("job"), TenantID: actor.TenantID, Kind: "verify_subject", SubjectType: subject.Type, SubjectID: subject.ID, Payload: map[string]any{"result_id": result.ID}, CreatedAt: now}); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	return result, nil
}
