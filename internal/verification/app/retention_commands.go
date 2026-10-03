package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	MaxRetentionPolicyBytes      = 8 * 1024 * 1024
	MaxRetentionObservationBytes = 4 * 1024 * 1024
	MaxRetentionObservationFacts = 4096
)

type RetentionPolicyReader interface {
	ReadObjectRetentionPolicy(context.Context, string, string) (verificationdomain.ObjectRetentionPolicy, error)
}
type RetentionPolicyRepository interface {
	GetObjectRetentionPolicyForUpdate(context.Context, string, string) (verificationdomain.ObjectRetentionPolicy, error)
	InsertObjectRetentionPolicy(context.Context, verificationdomain.ObjectRetentionPolicy) error
	UpdateObjectRetentionPolicy(context.Context, verificationdomain.ObjectRetentionPolicy, string) error
}
type RetentionTransaction interface {
	RetentionPolicyRepository
	application.Authorizer
	application.AuditAppender
}
type RetentionTransactions interface {
	ExecuteRetentionCommand(context.Context, func(context.Context, RetentionTransaction) error) error
}
type RetentionCommandConfig struct {
	Reader       RetentionPolicyReader
	Transactions RetentionTransactions
	Verifier     RetentionVerifier
	Hasher       CanonicalHasher
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type RetentionCommands struct {
	reader            RetentionPolicyReader
	transactions      RetentionTransactions
	retentionVerifier RetentionVerifier
	canonicalHasher   CanonicalHasher
	authorizer        application.Authorizer
	clock             application.Clock
	ids               application.IDGenerator
}

func NewRetentionCommands(config RetentionCommandConfig) (*RetentionCommands, error) {
	if config.Reader == nil || config.Transactions == nil || config.Verifier == nil || config.Hasher == nil || config.Authorizer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &RetentionCommands{reader: config.Reader, transactions: config.Transactions, retentionVerifier: config.Verifier, canonicalHasher: config.Hasher, authorizer: config.Authorizer, clock: config.Clock, ids: config.IDs}, nil
}
func (s *RetentionCommands) authorize(ctx context.Context, actor identitydomain.Actor, scope string) error {
	return s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scope, TenantWide: true})
}
func (s *RetentionCommands) auditEvent(actor identitydomain.Actor, at time.Time, kind, id string) application.AuditEvent {
	return application.AuditEvent{ID: s.ids.NewID("ace"), TenantID: actor.TenantID, EntryType: kind, SubjectType: "object_retention_policy", SubjectID: id, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at.UTC()}
}
func (s *Service) retentionCommands() (*RetentionCommands, error) {
	return NewRetentionCommands(RetentionCommandConfig{Reader: s.integrity, Transactions: serviceRetentionTransactions{s.transactions}, Verifier: s.retentionVerifier, Hasher: s.canonicalHasher, Authorizer: s.authorizer, Clock: s.clock, IDs: s.ids})
}
func (s *Service) CreateObjectRetentionPolicy(ctx context.Context, actor identitydomain.Actor, input CreateObjectRetentionPolicyInput) (verificationdomain.ObjectRetentionPolicy, error) {
	commands, err := s.retentionCommands()
	if err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	return commands.CreateObjectRetentionPolicy(ctx, actor, input)
}
func (s *Service) VerifyObjectRetentionPolicy(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	commands, err := s.retentionCommands()
	if err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	return commands.VerifyObjectRetentionPolicy(ctx, actor, id)
}

type serviceRetentionTransactions struct{ transactions TransactionRunner }

func (t serviceRetentionTransactions) ExecuteRetentionCommand(ctx context.Context, command func(context.Context, RetentionTransaction) error) error {
	return t.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		repo, ok := tx.Verification().(RetentionPolicyRepository)
		if !ok {
			return ErrValidation
		}
		return command(ctx, serviceRetentionTransaction{repo, tx.Authorization(), tx.Audit()})
	})
}

type serviceRetentionTransaction struct {
	RetentionPolicyRepository
	application.Authorizer
	application.AuditAppender
}
