package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var ErrVerificationFailed = errors.New("public transparency proof fetch failed")

const PublicTransparencyFetchTimeout = 30 * time.Second

type PublicTransparencyFetchSource struct {
	Entry    d.PublicTransparencyLogEntry
	Endpoint string
}
type PublicTransparencyProofRequest struct{ TenantID, LogID, EntryID, Endpoint, ExternalID, EntryHash string }

// Provider diagnostics are not part of this port and cannot assign assurance.
type PublicTransparencyFetchedProof struct {
	ExternalID string
	Proof      PublicTransparencyProofInput
}
type PublicTransparencyProofFetcher interface {
	FetchTransparencyProof(context.Context, PublicTransparencyProofRequest) (PublicTransparencyFetchedProof, error)
}
type PublicTransparencyFetchTransaction interface {
	PublicTransparencyVerificationTransaction
	ReadPublicTransparencyFetch(context.Context, string, string) (PublicTransparencyFetchSource, error)
}
type PublicTransparencyFetchTransactions interface {
	ExecutePublicTransparencyFetch(context.Context, string, func(context.Context, PublicTransparencyFetchTransaction) error) error
}
type PublicTransparencyFetchConfig struct {
	Transactions PublicTransparencyFetchTransactions
	Fetcher      PublicTransparencyProofFetcher
	Clock        application.Clock
	IDs          application.IDGenerator
}
type PublicTransparencyFetchCommands struct{ config PublicTransparencyFetchConfig }

func NewPublicTransparencyFetchCommands(c PublicTransparencyFetchConfig) (*PublicTransparencyFetchCommands, error) {
	if c.Transactions == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &PublicTransparencyFetchCommands{c}, nil
}
func NormalizePublicTransparencyFetchID(id string) (string, error) {
	if !anomalyText(id, MaxPublicTransparencyIDBytes) || strings.TrimSpace(id) == "" {
		return "", ErrValidation
	}
	return strings.TrimSpace(id), nil
}
func ValidatePublicTransparencyFetchSource(tenant, id string, s PublicTransparencyFetchSource) error {
	if err := ValidatePublicTransparencyVerificationSource(tenant, id, s.Entry); err != nil {
		return err
	}
	_, err := normalizePublicTransparencyEndpoint(s.Endpoint)
	return err
}
func SamePublicTransparencyFetchSource(a, b PublicTransparencyFetchSource) bool {
	return strings.TrimSpace(a.Endpoint) == strings.TrimSpace(b.Endpoint) && SamePublicTransparencyAssessment(a.Entry, b.Entry)
}
func NormalizePublicTransparencyFetchedProof(s PublicTransparencyFetchSource, result PublicTransparencyFetchedProof) (PublicTransparencyProofInput, error) {
	if !anomalyText(result.ExternalID, MaxPublicTransparencyIDBytes) || (strings.TrimSpace(result.ExternalID) != "" && strings.TrimSpace(result.ExternalID) != s.Entry.ExternalID) {
		return PublicTransparencyProofInput{}, ErrVerificationFailed
	}
	in, err := NormalizePublicTransparencyProofInput(s.Entry.ID, result.Proof)
	if err != nil {
		return PublicTransparencyProofInput{}, ErrVerificationFailed
	}
	return in, nil
}
func (c *PublicTransparencyFetchCommands) authorize(ctx context.Context, a identitydomain.Actor, id string) (string, error) {
	if c == nil {
		return "", ErrValidation
	}
	if err := AuthorizePublicTransparencyMetadataActor(ctx, a); err != nil {
		return "", err
	}
	id, err := NormalizePublicTransparencyFetchID(id)
	if err != nil {
		return "", err
	}
	if c.config.Fetcher == nil {
		return "", ErrValidation
	}
	return id, nil
}
func (c *PublicTransparencyFetchCommands) AuthorizeFetchPublicTransparencyLogEntryProof(ctx context.Context, a identitydomain.Actor, id string) error {
	id, err := c.authorize(ctx, a, id)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecutePublicTransparencyFetch(ctx, a.TenantID, func(ctx context.Context, tx PublicTransparencyFetchTransaction) error {
		s, err := tx.ReadPublicTransparencyFetch(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if err := ValidatePublicTransparencyFetchSource(a.TenantID, id, s); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func (c *PublicTransparencyFetchCommands) FetchAndVerifyPublicTransparencyLogEntry(ctx context.Context, a identitydomain.Actor, id string) (d.PublicTransparencyLogEntry, error) {
	id, err := c.authorize(ctx, a, id)
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	var out d.PublicTransparencyLogEntry
	err = c.config.Transactions.ExecutePublicTransparencyFetch(ctx, a.TenantID, func(ctx context.Context, tx PublicTransparencyFetchTransaction) error {
		s, err := tx.ReadPublicTransparencyFetch(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if err := ValidatePublicTransparencyFetchSource(a.TenantID, id, s); err != nil {
			return err
		}
		fetchCtx, cancel := context.WithTimeout(ctx, PublicTransparencyFetchTimeout)
		// Freeze only assessment coordinates before crossing the provider port;
		// diagnostics are irrelevant and must not turn into fetched authority.
		s.Entry.VerificationChecks, s.Entry.VerificationLimitations = nil, nil
		s.Entry = ClonePublicTransparencyEntry(s.Entry)
		defer cancel()
		result, err := c.config.Fetcher.FetchTransparencyProof(fetchCtx, PublicTransparencyProofRequest{TenantID: a.TenantID, LogID: s.Entry.LogID, EntryID: id, Endpoint: strings.TrimSpace(s.Endpoint), ExternalID: s.Entry.ExternalID, EntryHash: s.Entry.EntryHash})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || fetchCtx.Err() != nil {
			return ErrVerificationFailed
		}
		in, err := NormalizePublicTransparencyFetchedProof(s, result)
		if err != nil {
			return err
		}
		current, err := tx.ReadPublicTransparencyFetch(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if err := ValidatePublicTransparencyFetchSource(a.TenantID, id, current); err != nil {
			return err
		}
		if !SamePublicTransparencyFetchSource(s, current) {
			return ErrConflict
		}
		out, err = commitPublicTransparencyAssessment(ctx, tx, a, current.Entry, in, "fetched", c.config.Clock, c.config.IDs)
		return err
	})
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	return ClonePublicTransparencyEntry(out), nil
}
