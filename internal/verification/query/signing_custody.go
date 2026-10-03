package query

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	MaxSigningCustodyRecords = 4096
	MaxSigningCustodyBytes   = 8 * 1024 * 1024
)

var (
	ErrSigningCustodyValidation = errors.New("invalid signing custody query")
	ErrSigningCustodyProjection = errors.New("invalid signing custody projection")
)

// SigningCustodyReader returns only tenant-owned provider and retention-policy
// records from one committed snapshot. It must enforce the combined record
// and serialized-byte budgets without truncating a successful report. Signing
// key material, uploaded objects and other tenant state are never selected.
type SigningCustodyReader interface {
	ReadSigningCustodySnapshot(context.Context, string) (verificationapp.SigningCustodySnapshot, error)
}

type SigningCustody struct {
	reader SigningCustodyReader
	now    func() time.Time
}

func NewSigningCustody(reader SigningCustodyReader, now func() time.Time) (*SigningCustody, error) {
	if reader == nil || now == nil {
		return nil, ErrSigningCustodyValidation
	}
	return &SigningCustody{reader: reader, now: now}, nil
}

func (s *SigningCustody) Report(ctx context.Context, actor identitydomain.Actor) (verificationdomain.SigningCustodyReviewReport, error) {
	var empty verificationdomain.SigningCustodyReviewReport
	if s == nil || ctx == nil {
		return empty, ErrSigningCustodyValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, verificationapp.ScopeKeysAdmin); err != nil {
		return empty, err
	}
	snapshot, err := s.reader.ReadSigningCustodySnapshot(ctx, actor.TenantID)
	if err != nil {
		return empty, err
	}
	if snapshot.TenantID != actor.TenantID || len(snapshot.SigningProviders) > MaxSigningCustodyRecords || len(snapshot.ObjectRetentionPolicies) > MaxSigningCustodyRecords-len(snapshot.SigningProviders) {
		return empty, ErrSigningCustodyProjection
	}
	validID := func(id string) bool {
		return id != "" && len(id) <= 1024 && strings.TrimSpace(id) == id && utf8.ValidString(id) && !strings.ContainsRune(id, 0)
	}
	providerIDs := make(map[string]bool, len(snapshot.SigningProviders))
	for _, provider := range snapshot.SigningProviders {
		if provider.TenantID != actor.TenantID || !validID(provider.ID) || providerIDs[provider.ID] {
			return empty, ErrSigningCustodyProjection
		}
		providerIDs[provider.ID] = true
	}
	policyIDs := make(map[string]bool, len(snapshot.ObjectRetentionPolicies))
	for _, policy := range snapshot.ObjectRetentionPolicies {
		if policy.TenantID != actor.TenantID || !validID(policy.ID) || policyIDs[policy.ID] {
			return empty, ErrSigningCustodyProjection
		}
		policyIDs[policy.ID] = true
	}
	return verificationapp.BuildSigningCustodyReviewReport(snapshot, actor.TenantID, s.now().UTC())
}
