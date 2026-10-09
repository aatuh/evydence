package app

// Historical characterization only. Collector commands and pages are owned
// by focused Integration services, not the runtime Ledger surface.

import (
	"context"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

const (
	collectorTypeGitHubActions = "github_actions"
	collectorTypeGitLabCI      = "gitlab_ci"
	collectorTypeGenericCI     = "generic_ci"
	collectorTypeImportBundle  = "import_bundle"
	collectorStatusActive      = "active"
)

type CreateCollectorInput struct {
	Name    string
	Type    string
	Version string
	Scopes  []string
}

func (l *Ledger) CreateCollector(ctx context.Context, actor domain.Actor, in CreateCollectorInput) (domain.Collector, domain.APIKey, string, error) {
	if err := ctx.Err(); err != nil {
		return domain.Collector{}, domain.APIKey{}, "", err
	}
	if err := require(actor, ScopeCollectorAdmin); err != nil {
		return domain.Collector{}, domain.APIKey{}, "", err
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Type = strings.TrimSpace(in.Type)
	in.Version = strings.TrimSpace(in.Version)
	if in.Name == "" || in.Version == "" || !validCollectorType(in.Type) {
		return domain.Collector{}, domain.APIKey{}, "", ErrValidation
	}
	scopes := in.Scopes
	if len(scopes) == 0 {
		scopes = []string{ScopeBuildWrite, ScopeEvidenceWrite}
	}
	if !validCollectorScopes(scopes) {
		return domain.Collector{}, domain.APIKey{}, "", ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.collectors {
		if existing.TenantID == actor.TenantID && existing.Name == in.Name {
			return domain.Collector{}, domain.APIKey{}, "", ErrConflict
		}
	}
	var key domain.APIKey
	var secret string
	if l.unitOfWork != nil {
		key, secret = l.newAPIKey(actor.TenantID, "collector:"+in.Name, scopes, nil)
	} else {
		var err error
		key, secret, err = l.createAPIKeyLocked(actor.TenantID, "collector:"+in.Name, scopes, nil)
		if err != nil {
			return domain.Collector{}, domain.APIKey{}, "", err
		}
	}
	collector := domain.Collector{
		ID:            newID("col"),
		TenantID:      actor.TenantID,
		Name:          in.Name,
		Type:          in.Type,
		Version:       in.Version,
		APIKeyID:      key.ID,
		Status:        collectorStatusActive,
		AllowedScopes: sortedStrings(scopes),
		SchemaVersion: domain.CollectorSchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertAPIKey(ctx, key); err != nil {
				return err
			}
			if err := repos.Builds.InsertCollector(ctx, collector); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(collector.CreatedAt, actor.TenantID, "collector.created", "collector", collector.ID, "api_key", actor.KeyID, "", ""))
			return err
		}); err != nil {
			return domain.Collector{}, domain.APIKey{}, "", err
		}
		l.apiKeys[key.ID] = key
		l.collectors[collector.ID] = collector
		l.publishCommittedAuditEntryLocked(entry)
		public := key
		public.Hash = ""
		return collector, public, secret, nil
	}
	l.collectors[collector.ID] = collector
	_, _ = l.appendChainLocked(actor.TenantID, "collector.created", "collector", collector.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Collector{}, domain.APIKey{}, "", err
	}
	key.Hash = ""
	return collector, key, secret, nil
}

func (l *Ledger) ListCollectors(ctx context.Context, actor domain.Actor) ([]domain.Collector, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeCollectorRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeResourceLocked(actor, ScopeCollectorRead, resourceRefs{}); err != nil {
		return nil, err
	}
	out := []domain.Collector{}
	for _, collector := range l.collectors {
		if collector.TenantID == actor.TenantID {
			out = append(out, collector)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
