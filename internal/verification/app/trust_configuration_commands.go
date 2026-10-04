package app

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	MaxTrustPolicyEntries   = 4096
	MaxTrustPolicyTextBytes = 1024 * 1024
)

type TrustConfigurationRepository interface {
	InsertSigningProvider(context.Context, verificationdomain.SigningProvider) error
	InsertDSSETrustRoot(context.Context, verificationdomain.DSSETrustRoot) error
}
type TrustConfigurationTransaction interface {
	TrustConfigurationRepository
	application.Authorizer
	application.AuditAppender
}
type TrustConfigurationTransactions interface {
	ExecuteTrustConfigurationCommand(context.Context, func(context.Context, TrustConfigurationTransaction) error) error
}
type TrustConfigurationConfig struct {
	Transactions TrustConfigurationTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type TrustConfigurationCommands struct {
	transactions TrustConfigurationTransactions
	authorizer   application.Authorizer
	clock        application.Clock
	ids          application.IDGenerator
}

func NewTrustConfigurationCommands(config TrustConfigurationConfig) (*TrustConfigurationCommands, error) {
	if config.Transactions == nil || config.Authorizer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &TrustConfigurationCommands{config.Transactions, config.Authorizer, config.Clock, config.IDs}, nil
}
func (s *TrustConfigurationCommands) authorize(ctx context.Context, actor identitydomain.Actor) error {
	return s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true})
}

// AuthorizeTrustConfiguration checks current tenant-wide authority before
// durable reservation or replay, without generating metadata or audit entries.
// A native transaction keeps the tenant fence/root lock until outer commit.
func (s *TrustConfigurationCommands) AuthorizeTrustConfiguration(ctx context.Context, actor identitydomain.Actor) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateActor(actor); err != nil {
		return err
	}
	if err := s.authorize(ctx, actor); err != nil {
		return err
	}
	return s.transactions.ExecuteTrustConfigurationCommand(ctx, func(ctx context.Context, tx TrustConfigurationTransaction) error {
		return tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true})
	})
}
func (s *TrustConfigurationCommands) auditEvent(actor identitydomain.Actor, at time.Time, kind, subject, id string) application.AuditEvent {
	return application.AuditEvent{ID: s.ids.NewID("ace"), TenantID: actor.TenantID, EntryType: kind, SubjectType: subject, SubjectID: id, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at.UTC()}
}
func (s *Service) trustConfigurationCommands() (*TrustConfigurationCommands, error) {
	return NewTrustConfigurationCommands(TrustConfigurationConfig{Transactions: serviceTrustConfigurationTransactions{s.transactions}, Authorizer: s.authorizer, Clock: s.clock, IDs: s.ids})
}
func (s *Service) CreateSigningProvider(ctx context.Context, actor identitydomain.Actor, input CreateSigningProviderInput) (verificationdomain.SigningProvider, error) {
	commands, err := s.trustConfigurationCommands()
	if err != nil {
		return verificationdomain.SigningProvider{}, err
	}
	return commands.CreateSigningProvider(ctx, actor, input)
}
func (s *Service) CreateDSSETrustRoot(ctx context.Context, actor identitydomain.Actor, input CreateDSSETrustRootInput) (verificationdomain.DSSETrustRoot, error) {
	commands, err := s.trustConfigurationCommands()
	if err != nil {
		return verificationdomain.DSSETrustRoot{}, err
	}
	return commands.CreateDSSETrustRoot(ctx, actor, input)
}

type serviceTrustConfigurationTransactions struct{ transactions TransactionRunner }

func (t serviceTrustConfigurationTransactions) ExecuteTrustConfigurationCommand(ctx context.Context, command func(context.Context, TrustConfigurationTransaction) error) error {
	return t.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		repo, ok := tx.Verification().(TrustConfigurationRepository)
		if !ok {
			return ErrValidation
		}
		return command(ctx, serviceTrustConfigurationTransaction{repo, tx.Authorization(), tx.Audit()})
	})
}

type serviceTrustConfigurationTransaction struct {
	TrustConfigurationRepository
	application.Authorizer
	application.AuditAppender
}

type CreateSigningProviderInput struct {
	Name      string
	Type      string
	KeyRef    string
	Encrypted bool
}

// NormalizeSigningProviderInput bounds raw operator input before trimming it.
// Provider references are metadata, never embedded credential material.
func NormalizeSigningProviderInput(input CreateSigningProviderInput) (CreateSigningProviderInput, error) {
	if !validRetentionText(input.Name, 4096) || !validRetentionText(input.Type, 4096) || !validRetentionText(input.KeyRef, 4096) {
		return CreateSigningProviderInput{}, ErrValidation
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Type = strings.TrimSpace(input.Type)
	input.KeyRef = strings.TrimSpace(input.KeyRef)
	if !validSigningProviderInput(input) {
		return CreateSigningProviderInput{}, ErrValidation
	}
	return input, nil
}

func (s *TrustConfigurationCommands) CreateSigningProvider(ctx context.Context, actor identitydomain.Actor, input CreateSigningProviderInput) (verificationdomain.SigningProvider, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.SigningProvider{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.SigningProvider{}, err
	}
	if err := s.authorize(ctx, actor); err != nil {
		return verificationdomain.SigningProvider{}, err
	}
	input, err := NormalizeSigningProviderInput(input)
	if err != nil {
		return verificationdomain.SigningProvider{}, err
	}
	now := s.clock.Now().UTC()
	provider := verificationdomain.SigningProvider{
		ID: s.ids.NewID("sp"), TenantID: actor.TenantID, Name: input.Name, Type: input.Type,
		Status: "active", KeyRef: input.KeyRef, Encrypted: input.Encrypted,
		SchemaVersion: verificationdomain.SigningProviderSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.ExecuteTrustConfigurationCommand(ctx, func(ctx context.Context, tx TrustConfigurationTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}); err != nil {
			return err
		}
		if err := tx.InsertSigningProvider(ctx, provider); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, s.auditEvent(actor, now, "signing_provider.created", "signing_provider", provider.ID))
		return err
	})
	if err != nil {
		return verificationdomain.SigningProvider{}, err
	}
	return provider, nil
}

type CreateDSSETrustRootInput struct {
	Name                  string
	KeyID                 string
	Algorithm             string
	PublicKey             string
	AllowedPredicateTypes []string
	ExpectedBuilderIDs    []string
	RequiredClaims        []string
}

// NormalizeDSSETrustRootInput preserves sorted, unique public policy
// metadata, while enforcing combined raw policy budgets before allocation.
func NormalizeDSSETrustRootInput(input CreateDSSETrustRootInput) (CreateDSSETrustRootInput, error) {
	if !validRetentionText(input.Name, 4096) || !validRetentionText(input.KeyID, 1024) || !validRetentionText(input.Algorithm, 4096) || !validRetentionText(input.PublicKey, 128) || !boundedTrustPolicy(input) {
		return CreateDSSETrustRootInput{}, ErrValidation
	}
	input.Name = strings.TrimSpace(input.Name)
	input.KeyID = strings.TrimSpace(input.KeyID)
	input.Algorithm = strings.TrimSpace(input.Algorithm)
	input.PublicKey = strings.TrimSpace(input.PublicKey)
	input.AllowedPredicateTypes = sortedTrimmedStrings(input.AllowedPredicateTypes)
	input.ExpectedBuilderIDs = sortedTrimmedStrings(input.ExpectedBuilderIDs)
	input.RequiredClaims = sortedTrimmedStrings(input.RequiredClaims)
	if !validDSSETrustRootInput(input) {
		return CreateDSSETrustRootInput{}, ErrValidation
	}
	return input, nil
}

func (s *TrustConfigurationCommands) CreateDSSETrustRoot(ctx context.Context, actor identitydomain.Actor, input CreateDSSETrustRootInput) (verificationdomain.DSSETrustRoot, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.DSSETrustRoot{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.DSSETrustRoot{}, err
	}
	if err := s.authorize(ctx, actor); err != nil {
		return verificationdomain.DSSETrustRoot{}, err
	}
	input, err := NormalizeDSSETrustRootInput(input)
	if err != nil {
		return verificationdomain.DSSETrustRoot{}, err
	}
	now := s.clock.Now().UTC()
	root := verificationdomain.DSSETrustRoot{
		ID: s.ids.NewID("dtr"), TenantID: actor.TenantID, Name: input.Name, KeyID: input.KeyID,
		Algorithm: input.Algorithm, PublicKey: input.PublicKey,
		AllowedPredicateTypes: append([]string(nil), input.AllowedPredicateTypes...),
		ExpectedBuilderIDs:    append([]string(nil), input.ExpectedBuilderIDs...), RequiredClaims: append([]string(nil), input.RequiredClaims...),
		Status: "active", SchemaVersion: verificationdomain.DSSETrustRootSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.ExecuteTrustConfigurationCommand(ctx, func(ctx context.Context, tx TrustConfigurationTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}); err != nil {
			return err
		}
		if err := tx.InsertDSSETrustRoot(ctx, root); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, s.auditEvent(actor, now, "dsse_trust_root.created", "dsse_trust_root", root.ID))
		return err
	})
	if err != nil {
		return verificationdomain.DSSETrustRoot{}, err
	}
	return cloneDSSETrustRoot(root), nil
}

// Check raw sizes before copying or sorting operator-supplied policy lists.
func boundedTrustPolicy(input CreateDSSETrustRootInput) bool {
	count := 0
	remaining := MaxTrustPolicyTextBytes
	for _, list := range [][]string{input.AllowedPredicateTypes, input.ExpectedBuilderIDs, input.RequiredClaims} {
		if len(list) > MaxTrustPolicyEntries-count {
			return false
		}
		count += len(list)
		for _, value := range list {
			if len(value) > 4096 || len(value) > remaining || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
				return false
			}
			remaining -= len(value)
		}
	}
	return true
}
