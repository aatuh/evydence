package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Unchanged historical aggregate facades remain in the legacy test oracle.
type CreateObjectRetentionPolicyInput struct {
	Name                    string
	ObjectPrefix            string
	ObjectKey               string
	Mode                    string
	RetentionDays           int
	MaxVerificationAgeHours int
	RequireLegalHold        bool
}

func (l *Ledger) CreateObjectRetentionPolicy(ctx context.Context, actor domain.Actor, in CreateObjectRetentionPolicyInput) (domain.ObjectRetentionPolicy, error) {
	value, err := l.legacyVerificationCommands().CreateObjectRetentionPolicy(ctx, actor, verificationapp.CreateObjectRetentionPolicyInput{
		Name: in.Name, ObjectPrefix: in.ObjectPrefix, ObjectKey: in.ObjectKey, Mode: in.Mode,
		RetentionDays: in.RetentionDays, MaxVerificationAgeHours: in.MaxVerificationAgeHours,
		RequireLegalHold: in.RequireLegalHold,
	})
	return objectRetentionPolicyFromVerificationContext(value), fromVerificationContextError(err)
}

func (l *Ledger) VerifyObjectRetentionPolicy(ctx context.Context, actor domain.Actor, id string) (domain.ObjectRetentionPolicy, error) {
	value, err := l.legacyVerificationCommands().VerifyObjectRetentionPolicy(ctx, actor, id)
	return objectRetentionPolicyFromVerificationContext(value), fromVerificationContextError(err)
}
