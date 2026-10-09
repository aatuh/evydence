package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const MaxSigningRotationKeys = 4096

// SigningKeyRepository reads only public metadata. The durable adapter locks
// the tenant before key rows, including when there are no local keys yet.
type SigningKeyRepository interface {
	ListLocalSigningKeysForUpdate(context.Context, string) ([]verificationdomain.SigningKey, error)
	GetSigningKeyForUpdate(context.Context, string, string) (verificationdomain.SigningKey, error)
	UpdateSigningKey(context.Context, verificationdomain.SigningKey, string) error
	InsertSigningKey(context.Context, PreparedSigningKey) error
}
type SigningKeyTransaction interface {
	SigningKeyRepository
	application.Authorizer
	application.AuditAppender
}
type SigningKeyTransactions interface {
	ExecuteSigningKeyCommand(context.Context, func(context.Context, SigningKeyTransaction) error) error
}
type SigningKeyCommandConfig struct {
	Transactions SigningKeyTransactions
	KeyFactory   KeyFactory
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}

// SigningKeyCommands owns atomic key lifecycle changes, not verification,
// exports, provider calls or unrelated tenant state.
type SigningKeyCommands struct{ config SigningKeyCommandConfig }

func NewSigningKeyCommands(config SigningKeyCommandConfig) (*SigningKeyCommands, error) {
	if config.Transactions == nil || config.KeyFactory == nil || config.Authorizer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &SigningKeyCommands{config}, nil
}
func (s *SigningKeyCommands) authorize(ctx context.Context, actor identitydomain.Actor) error {
	return s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true})
}
func (s *SigningKeyCommands) auditEvent(actor identitydomain.Actor, at time.Time, kind, id string) application.AuditEvent {
	return application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: kind, SubjectType: "signing_key", SubjectID: id, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at.UTC()}
}

func (s *Service) signingKeyCommands() (*SigningKeyCommands, error) {
	return NewSigningKeyCommands(SigningKeyCommandConfig{Transactions: serviceSigningKeyTransactions{s.transactions}, KeyFactory: s.keyFactory, Authorizer: s.authorizer, Clock: s.clock, IDs: s.ids})
}
func (s *Service) RotateSigningKey(ctx context.Context, actor identitydomain.Actor, reason string) (verificationdomain.SigningKey, error) {
	commands, err := s.signingKeyCommands()
	if err != nil {
		return verificationdomain.SigningKey{}, err
	}
	return commands.RotateSigningKey(ctx, actor, reason)
}
func (s *Service) RevokeSigningKey(ctx context.Context, actor identitydomain.Actor, id string, input SigningKeyRevocationInput) (verificationdomain.SigningKey, error) {
	commands, err := s.signingKeyCommands()
	if err != nil {
		return verificationdomain.SigningKey{}, err
	}
	return commands.RevokeSigningKey(ctx, actor, id, input)
}

type serviceSigningKeyTransactions struct{ transactions TransactionRunner }

func (t serviceSigningKeyTransactions) ExecuteSigningKeyCommand(ctx context.Context, command func(context.Context, SigningKeyTransaction) error) error {
	return t.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		repo, ok := tx.Verification().(SigningKeyRepository)
		if !ok {
			return ErrValidation
		}
		return command(ctx, serviceSigningKeyTransaction{repo, tx.Authorization(), tx.Audit()})
	})
}

type serviceSigningKeyTransaction struct {
	SigningKeyRepository
	application.Authorizer
	application.AuditAppender
}
