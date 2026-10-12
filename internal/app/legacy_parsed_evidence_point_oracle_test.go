package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical getters are package-local oracles, not runtime ports.
func (l *Ledger) GetSBOM(ctx context.Context, actor domain.Actor, id string) (domain.SBOM, error) {
	if err := ctx.Err(); err != nil {
		return domain.SBOM{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.SBOM{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.SBOM{}, err
	}
	sbom, ok := l.sboms[strings.TrimSpace(id)]
	if !ok || sbom.TenantID != actor.TenantID {
		return domain.SBOM{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: sbom.ReleaseID}); err != nil {
		return domain.SBOM{}, err
	}
	return sbom, nil
}

func (l *Ledger) GetVulnerabilityScan(ctx context.Context, actor domain.Actor, id string) (domain.VulnerabilityScan, error) {
	if err := ctx.Err(); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	scan, ok := l.scans[strings.TrimSpace(id)]
	if !ok || scan.TenantID != actor.TenantID {
		return domain.VulnerabilityScan{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: scan.ReleaseID}); err != nil {
		return domain.VulnerabilityScan{}, err
	}
	return scan, nil
}

func (l *Ledger) GetOpenAPIContract(ctx context.Context, actor domain.Actor, id string) (domain.OpenAPIContract, error) {
	if err := ctx.Err(); err != nil {
		return domain.OpenAPIContract{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.OpenAPIContract{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.OpenAPIContract{}, err
	}
	contract, ok := l.contracts[strings.TrimSpace(id)]
	if !ok || contract.TenantID != actor.TenantID {
		return domain.OpenAPIContract{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ProductID: contract.ProductID, ReleaseID: contract.ReleaseID}); err != nil {
		return domain.OpenAPIContract{}, err
	}
	return contract, nil
}
