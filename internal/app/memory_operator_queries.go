package app

import (
	"context"

	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

// Test-backend scalar projections use current transaction ownership/count
// fields, never Ledger or private metadata. Memory models queued jobs only and
// no reconciliation receipts; its zeros do not prove durable SQL behavior.
func (r memoryEnterpriseRepository) ReadMetricsSnapshot(ctx context.Context, tenant string, includeOutbox bool) (operationsquery.MetricsSnapshot, error) {
	var out operationsquery.MetricsSnapshot
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		out.ResourceCounts = map[string]int{
			"audit_chain_entries": len(s.AuditEntries[tenant]), "artifact_signatures": 0,
			"cosign_verifications": 0, "evidence": 0, "merkle_batches": 0,
			"object_retention_policies": 0, "release_bundles": 0, "transparency_checkpoints": 0,
		}
		for _, v := range s.Evidence {
			if v.TenantID == tenant {
				out.ResourceCounts["evidence"]++
			}
		}
		for _, v := range s.ArtifactSignatures {
			if v.TenantID == tenant {
				out.ResourceCounts["artifact_signatures"]++
			}
		}
		for _, v := range s.CosignVerifications {
			if v.TenantID == tenant {
				out.ResourceCounts["cosign_verifications"]++
			}
		}
		for _, v := range s.MerkleBatches {
			if v.TenantID == tenant {
				out.ResourceCounts["merkle_batches"]++
			}
		}
		for _, v := range s.ObjectRetentionPolicies {
			if v.TenantID == tenant {
				out.ResourceCounts["object_retention_policies"]++
			}
		}
		for _, v := range s.ReleaseBundles {
			if v.TenantID == tenant {
				out.ResourceCounts["release_bundles"]++
			}
		}
		for _, v := range s.TransparencyCheckpoints {
			if v.TenantID == tenant {
				out.ResourceCounts["transparency_checkpoints"]++
			}
		}
		maxInt := int(^uint(0) >> 1)
		for _, v := range s.CustomerPortalAccess {
			if v.TenantID != tenant {
				continue
			}
			if v.FailedAccessCount < 0 || v.FailedAccessCount > maxInt-out.CustomerPortalFailedAccessCount {
				return operationsquery.ErrInvalidProjection
			}
			out.CustomerPortalFailedAccessCount += v.FailedAccessCount
			if v.RevokedAt != nil {
				out.CustomerPortalRevokedAccessCount++
			}
		}
		if includeOutbox {
			out.Outbox = &operationsquery.OutboxCounts{PendingJobs: len(s.OutboxJobs)}
			for _, v := range s.OutboxJobs {
				if v.CreatedAt.IsZero() {
					return operationsquery.ErrInvalidProjection
				}
				if out.Outbox.OldestPendingCreatedAt.IsZero() || v.CreatedAt.Before(out.Outbox.OldestPendingCreatedAt) {
					out.Outbox.OldestPendingCreatedAt = v.CreatedAt.UTC()
				}
			}
		}
		return nil
	})
	if err != nil {
		return operationsquery.MetricsSnapshot{}, err
	}
	return out, nil
}

func (r memoryEnterpriseRepository) ReadInstanceCounts(ctx context.Context) (operationsquery.InstanceCounts, error) {
	if ctx == nil || r.uow == nil {
		return operationsquery.InstanceCounts{}, ErrValidation
	}
	var out operationsquery.InstanceCounts
	err := r.uow.mutate(ctx, func(s *MemoryUnitOfWorkSnapshot) error {
		out = operationsquery.InstanceCounts{Tenants: len(s.Tenants), Users: len(s.Users), Collectors: len(s.Collectors), Evidence: len(s.Evidence)}
		return nil
	})
	if err != nil {
		return operationsquery.InstanceCounts{}, err
	}
	return out, nil
}

var (
	_ operationsquery.MetricsReader        = memoryEnterpriseRepository{}
	_ operationsquery.InstanceCountsReader = memoryEnterpriseRepository{}
)
