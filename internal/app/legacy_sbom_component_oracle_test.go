package app

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Historical aggregate behavior remains only as an unchanged test oracle.
// Focused query fixtures use current repository rows instead.
type ListSBOMComponentsInput struct {
	SBOMID     string
	ReleaseID  string
	ArtifactID string
	Query      string
	PURL       string
	Limit      int
}

func (l *Ledger) ListSBOMComponents(ctx context.Context, actor domain.Actor, in ListSBOMComponentsInput) ([]domain.SBOMComponentRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return nil, err
	}
	in.SBOMID = strings.TrimSpace(in.SBOMID)
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	in.ArtifactID = strings.TrimSpace(in.ArtifactID)
	in.Query = strings.ToLower(strings.TrimSpace(in.Query))
	in.PURL = strings.TrimSpace(in.PURL)
	if in.Limit < 0 || in.Limit > 500 {
		return nil, ErrValidation
	}
	if in.Limit == 0 {
		in.Limit = 100
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return nil, err
	}
	if in.SBOMID != "" {
		sbom, ok := l.sboms[in.SBOMID]
		if !ok || sbom.TenantID != actor.TenantID {
			return nil, ErrNotFound
		}
	}
	ids := make([]string, 0, len(l.sboms))
	for id := range l.sboms {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]domain.SBOMComponentRecord, 0)
	for _, id := range ids {
		sbom := l.sboms[id]
		if sbom.TenantID != actor.TenantID {
			continue
		}
		if in.SBOMID != "" && sbom.ID != in.SBOMID {
			continue
		}
		if in.ReleaseID != "" && sbom.ReleaseID != in.ReleaseID {
			continue
		}
		if in.ArtifactID != "" && sbom.ArtifactID != in.ArtifactID {
			continue
		}
		if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: sbom.ReleaseID, ArtifactID: sbom.ArtifactID}); err != nil {
			return nil, err
		}
		for index, component := range sbom.Components {
			if !sbomComponentMatches(component, in.Query, in.PURL) {
				continue
			}
			out = append(out, domain.SBOMComponentRecord{ID: sbom.ID + ":" + strconv.Itoa(index), SBOMID: sbom.ID, ReleaseID: sbom.ReleaseID, ArtifactID: sbom.ArtifactID, Format: sbom.Format, SpecVersion: sbom.SpecVersion, Component: component})
			if len(out) >= in.Limit {
				return out, nil
			}
		}
	}
	return out, nil
}

func sbomComponentMatches(component domain.SBOMComponent, query, purl string) bool {
	if purl != "" && component.PURL != purl {
		return false
	}
	if query == "" {
		return true
	}
	haystack := strings.ToLower(component.Name + "\n" + component.Version + "\n" + component.PURL)
	return strings.Contains(haystack, query)
}
