// Package query owns bounded, authorized evidence reads.
package query

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const scopeEvidenceRead = "evidence:read"

var (
	ErrValidation = errors.New("invalid evidence query")
	ErrNotFound   = errors.New("evidence not found")
	ErrConflict   = errors.New("invalid evidence projection")
)

// EvidencePoint carries one tenant-owned item and the parent coordinates
// resolved in the same database snapshot. The reader validates their
// relationships before returning them. Worker-owned items require validated
// selected parser/source/audit facts from the same committed snapshot.
type EvidencePoint struct {
	Item                      evidencedomain.EvidenceItem
	ProductID                 string
	ProjectID                 string
	ReleaseID                 string
	WorkerProjectionValidated bool
}

// EvidenceReadGuard authorizes resolved coordinates before the reader loads
// metadata, provenance or lifecycle detail. It must be invoked inside the
// same snapshot used for returning the evidence point.
type EvidenceReadGuard func(application.ResourceReferences) error

type EvidencePointReader interface {
	GetEvidencePoint(context.Context, string, string, EvidenceReadGuard) (EvidencePoint, error)
}

type EvidencePoints struct{ reader EvidencePointReader }

func NewEvidencePoints(reader EvidencePointReader) (*EvidencePoints, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &EvidencePoints{reader: reader}, nil
}

func (s *EvidencePoints) GetEvidence(ctx context.Context, actor identitydomain.Actor, id string) (evidencedomain.EvidenceItem, error) {
	if s == nil || ctx == nil {
		return evidencedomain.EvidenceItem{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if err := authorizeEvidenceRead(actor, EvidencePoint{}, true); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return evidencedomain.EvidenceItem{}, ErrNotFound
	}
	if !validEvidenceReadID(id) {
		return evidencedomain.EvidenceItem{}, ErrValidation
	}
	point, err := s.reader.GetEvidencePoint(ctx, actor.TenantID, id, evidenceReadGuard(ctx, actor))
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	if !validEvidencePoint(point, actor.TenantID, id) {
		return evidencedomain.EvidenceItem{}, ErrConflict
	}
	if err := authorizeEvidenceRead(actor, point, false); err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	return point.Item, nil
}

func validEvidencePoint(point EvidencePoint, tenantID, id string) bool {
	item := point.Item
	if evidencedomain.RequiresWorkerProjection(item.Type) && !point.WorkerProjectionValidated {
		return false
	}
	if item.ID != id || item.TenantID != tenantID || strings.TrimSpace(item.ID) != item.ID || strings.TrimSpace(item.TenantID) != item.TenantID {
		return false
	}
	for _, coordinate := range []string{item.ProductID, item.ProjectID, item.ReleaseID, item.BuildID, item.DeploymentID, point.ProductID, point.ProjectID, point.ReleaseID} {
		if strings.TrimSpace(coordinate) != coordinate {
			return false
		}
	}
	for _, reference := range item.RelatedEvidenceRefs {
		if reference.Type == "" || reference.ID == "" || strings.TrimSpace(reference.Type) != reference.Type || strings.TrimSpace(reference.ID) != reference.ID || strings.TrimSpace(reference.Relationship) != reference.Relationship {
			return false
		}
	}
	if strings.TrimSpace(item.Supersedes) != item.Supersedes || strings.TrimSpace(item.SupersededBy) != item.SupersededBy {
		return false
	}
	if item.ProductID != "" && point.ProductID != item.ProductID || item.ProjectID != "" && point.ProjectID != item.ProjectID || item.ReleaseID != "" && point.ReleaseID != item.ReleaseID {
		return false
	}
	if item.ProductID == "" && item.ProjectID == "" && item.ReleaseID == "" && item.BuildID == "" && item.DeploymentID == "" {
		return point.ProductID == "" && point.ProjectID == "" && point.ReleaseID == ""
	}
	if point.ProductID == "" || (item.ProjectID != "" || item.BuildID != "") && point.ProjectID == "" {
		return false
	}
	if (item.ReleaseID != "" || item.BuildID != "" || item.DeploymentID != "") && point.ReleaseID == "" {
		return false
	}
	if item.ProjectID == "" && item.BuildID == "" && point.ProjectID != "" || item.ReleaseID == "" && item.BuildID == "" && item.DeploymentID == "" && point.ReleaseID != "" {
		return false
	}
	return true
}

func validEvidenceReadID(id string) bool {
	return id != "" && len(id) <= 1024 && utf8.ValidString(id) && !strings.ContainsRune(id, 0)
}
func evidenceReadGuard(ctx context.Context, actor identitydomain.Actor) EvidenceReadGuard {
	return func(refs application.ResourceReferences) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, BuildID: refs.BuildID, DeploymentID: refs.DeploymentID}) {
			return ErrConflict
		}
		return authorizeEvidenceRead(actor, EvidencePoint{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID}, false)
	}
}

func authorizeEvidenceRead(actor identitydomain.Actor, point EvidencePoint, scopeOnly bool) error {
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return application.ErrUnauthorized
	}
	if !actor.HasScope(scopeEvidenceRead) && !actor.HasScope("admin") {
		return application.ErrForbidden
	}
	if scopeOnly || actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return nil
	}
	for _, grant := range actor.ResourceGrants {
		if !evidenceGrantHasScope(grant) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return nil
			}
		case "product":
			if point.ProductID != "" && grant.ResourceID == point.ProductID {
				return nil
			}
		case "project":
			if point.ProjectID != "" && grant.ResourceID == point.ProjectID {
				return nil
			}
		case "release":
			if point.ReleaseID != "" && grant.ResourceID == point.ReleaseID {
				return nil
			}
		}
	}
	return application.ErrForbidden
}

func evidenceGrantHasScope(grant identitydomain.ResourceGrant) bool {
	for _, scope := range grant.Scopes {
		if scope == scopeEvidenceRead || scope == "admin" || scope == "*" {
			return true
		}
	}
	return false
}
