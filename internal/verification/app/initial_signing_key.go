package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type InitialSigningKeyWriter interface {
	InsertSigningKey(context.Context, PreparedSigningKey) error
}

type InitialSigningKeyConfig struct {
	KeyFactory KeyFactory
	Clock      application.Clock
}

type InitialSigningKeyCommands struct{ config InitialSigningKeyConfig }

func NewInitialSigningKeyCommands(c InitialSigningKeyConfig) (*InitialSigningKeyCommands, error) {
	if c.KeyFactory == nil || c.Clock == nil {
		return nil, ErrValidation
	}
	return &InitialSigningKeyCommands{c}, nil
}

func (s *InitialSigningKeyCommands) PrepareInitialSigningKey(ctx context.Context, tenantID string) (PreparedSigningKey, error) {
	if err := contextError(ctx); err != nil {
		return PreparedSigningKey{}, err
	}
	if s == nil || len(tenantID) > 1024 || !validSigningKeyText(tenantID) {
		return PreparedSigningKey{}, ErrValidation
	}
	tenantID = strings.TrimSpace(tenantID)
	now := s.config.Clock.Now().UTC()
	generated, err := s.config.KeyFactory.GenerateSigningKey(ctx, tenantID, verificationdomain.SigningKeyDefaultProvider, 1, now)
	defer clear(generated.PrivateMaterial)
	if err != nil {
		return PreparedSigningKey{}, err
	}
	prepared := clonePreparedSigningKey(generated)
	if !validPreparedSigningKey(prepared, tenantID, verificationdomain.SigningKeyDefaultProvider, 1, now) {
		clear(prepared.PrivateMaterial)
		return PreparedSigningKey{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		clear(prepared.PrivateMaterial)
		return PreparedSigningKey{}, err
	}
	return prepared, nil
}

func (s *InitialSigningKeyCommands) CommitInitialSigningKey(ctx context.Context, writer InitialSigningKeyWriter, tenantID string, prepared PreparedSigningKey) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if s == nil || writer == nil || len(tenantID) > 1024 || !validSigningKeyText(tenantID) {
		return ErrValidation
	}
	tenantID = strings.TrimSpace(tenantID)
	prepared = clonePreparedSigningKey(prepared)
	defer clear(prepared.PrivateMaterial)
	if !validPreparedSigningKey(prepared, tenantID, verificationdomain.SigningKeyDefaultProvider, 1, s.config.Clock.Now().UTC()) {
		return ErrValidation
	}
	if err := writer.InsertSigningKey(ctx, prepared); err != nil {
		return err
	}
	return ctx.Err()
}
