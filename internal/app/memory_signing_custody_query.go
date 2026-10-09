package app

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

var _ verificationquery.SigningCustodyReader = memoryIntegrityRepository{}

// This typed test model bounds owned coordinates and encoded public DTOs. It
// never reads signing keys or payloads and does not prove SQL JSON shapes,
// transfer/work limits, row locks or durability.
func (r memoryIntegrityRepository) ReadSigningCustodySnapshot(ctx context.Context, tenant string) (verificationapp.SigningCustodySnapshot, error) {
	var out verificationapp.SigningCustodySnapshot
	err := memoryGovernanceRead(ctx, r.uow, tenant, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		providers, policies := make([]string, 0), make([]string, 0)
		for id, provider := range s.SigningProviders {
			if err := ctx.Err(); err != nil {
				return err
			}
			if provider.TenantID != tenant {
				continue
			}
			if !validMemoryCustodyID(id, provider.ID) || len(providers) == verificationquery.MaxSigningCustodyRecords {
				return verificationquery.ErrSigningCustodyProjection
			}
			providers = append(providers, id)
		}
		for id, policy := range s.ObjectRetentionPolicies {
			if err := ctx.Err(); err != nil {
				return err
			}
			if policy.TenantID != tenant {
				continue
			}
			if !validMemoryCustodyID(id, policy.ID) || len(policies) == verificationquery.MaxSigningCustodyRecords-len(providers) {
				return verificationquery.ErrSigningCustodyProjection
			}
			policies = append(policies, id)
		}
		slices.Sort(providers)
		slices.Sort(policies)
		out = verificationapp.SigningCustodySnapshot{TenantID: tenant, SigningProviders: make([]verificationdomain.SigningProvider, 0, len(providers)), ObjectRetentionPolicies: make([]verificationdomain.ObjectRetentionPolicy, 0, len(policies))}
		remaining := verificationquery.MaxSigningCustodyBytes
		account := func(value any) error {
			raw, err := json.Marshal(value)
			if err != nil || len(raw) > remaining {
				return verificationquery.ErrSigningCustodyProjection
			}
			remaining -= len(raw)
			return nil
		}
		for _, id := range providers {
			if err := ctx.Err(); err != nil {
				return err
			}
			provider := s.SigningProviders[id]
			if err := account(provider); err != nil {
				return err
			}
			out.SigningProviders = append(out.SigningProviders, domain.SigningProviderToContextModel(provider))
		}
		for _, id := range policies {
			if err := ctx.Err(); err != nil {
				return err
			}
			policy := s.ObjectRetentionPolicies[id]
			if err := account(policy); err != nil {
				return err
			}
			out.ObjectRetentionPolicies = append(out.ObjectRetentionPolicies, domain.ObjectRetentionPolicyToContextModel(policy))
		}
		return ctx.Err()
	})
	if err != nil {
		return verificationapp.SigningCustodySnapshot{}, err
	}
	return out, nil
}

func validMemoryCustodyID(key, id string) bool {
	return key == id && id != "" && strings.TrimSpace(id) == id && memoryGovernanceText(id, 1024)
}
