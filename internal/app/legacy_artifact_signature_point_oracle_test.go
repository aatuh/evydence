package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) GetArtifactSignature(ctx context.Context, actor domain.Actor, id string) (domain.ArtifactSignature, error) {
	if err := ctx.Err(); err != nil {
		return domain.ArtifactSignature{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.ArtifactSignature{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sig, ok := l.artifactSigs[strings.TrimSpace(id)]
	if !ok || sig.TenantID != actor.TenantID {
		return domain.ArtifactSignature{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ArtifactID: sig.ArtifactID}); err != nil {
		return domain.ArtifactSignature{}, err
	}
	return sig, nil
}
