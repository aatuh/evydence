package query

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const scopeSignatureRead = "evidence:read"

var (
	ErrSignatureValidation = errors.New("invalid artifact signature query")
	ErrSignatureNotFound   = errors.New("artifact signature not found")
	ErrSignatureProjection = errors.New("invalid artifact signature projection")
)

// SignatureReadRequest contains visibility derived from the current actor,
// never from caller-supplied resource IDs. The reader must verify both the
// signature's artifact and one scoped association in one database statement.
type SignatureReadRequest struct {
	TenantID          string
	ID                string
	TenantWide        bool
	AllowedProductIDs []string
	AllowedProjectIDs []string
	AllowedReleaseIDs []string
}

type SignaturePoint struct {
	Signature      verificationdomain.ArtifactSignature
	ArtifactDigest string
	ProductID      string
	ProjectID      string
	ReleaseID      string
}

type ArtifactSignatureReader interface {
	GetArtifactSignaturePoint(context.Context, SignatureReadRequest) (SignaturePoint, error)
}

type ArtifactSignatures struct{ reader ArtifactSignatureReader }

func NewArtifactSignatures(reader ArtifactSignatureReader) (*ArtifactSignatures, error) {
	if reader == nil {
		return nil, ErrSignatureValidation
	}
	return &ArtifactSignatures{reader: reader}, nil
}

func (s *ArtifactSignatures) GetArtifactSignature(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.ArtifactSignature, error) {
	if s == nil || ctx == nil {
		return verificationdomain.ArtifactSignature{}, ErrSignatureValidation
	}
	if err := ctx.Err(); err != nil {
		return verificationdomain.ArtifactSignature{}, err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return verificationdomain.ArtifactSignature{}, application.ErrUnauthorized
	}
	if !actor.HasScope(scopeSignatureRead) && !actor.HasScope("admin") {
		return verificationdomain.ArtifactSignature{}, application.ErrForbidden
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return verificationdomain.ArtifactSignature{}, ErrSignatureNotFound
	}
	tenantWide, products, projects, releases := signatureVisibility(actor)
	if !tenantWide && len(products) == 0 && len(projects) == 0 && len(releases) == 0 {
		return verificationdomain.ArtifactSignature{}, application.ErrForbidden
	}
	request := SignatureReadRequest{TenantID: actor.TenantID, ID: id, TenantWide: tenantWide,
		AllowedProductIDs: products, AllowedProjectIDs: projects, AllowedReleaseIDs: releases}
	point, err := s.reader.GetArtifactSignaturePoint(ctx, request)
	if err != nil {
		return verificationdomain.ArtifactSignature{}, err
	}
	signature := point.Signature
	if signature.ID != id || signature.TenantID != actor.TenantID || signature.ArtifactID == "" ||
		signature.SubjectDigest == "" || signature.SubjectDigest != point.ArtifactDigest ||
		signature.Algorithm == "" || signature.Signature == "" || signature.SchemaVersion == "" || signature.CreatedAt.IsZero() {
		return verificationdomain.ArtifactSignature{}, ErrSignatureProjection
	}
	if !tenantWide {
		if point.ProductID == "" && point.ProjectID == "" && point.ReleaseID == "" {
			return verificationdomain.ArtifactSignature{}, application.ErrForbidden
		}
		if !hasSignatureCoordinate(products, point.ProductID) && !hasSignatureCoordinate(projects, point.ProjectID) && !hasSignatureCoordinate(releases, point.ReleaseID) {
			return verificationdomain.ArtifactSignature{}, ErrSignatureProjection
		}
	}
	return signature, nil
}

func signatureVisibility(actor identitydomain.Actor) (bool, []string, []string, []string) {
	if actor.UserID == "" || actor.KeyID != "" || actor.CollectorID != "" {
		return true, nil, nil, nil
	}
	products, projects, releases := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, grant := range actor.ResourceGrants {
		if !signatureGrantHasScope(grant) {
			continue
		}
		switch grant.ResourceType {
		case "", "tenant":
			if grant.ResourceID == "" || grant.ResourceID == actor.TenantID {
				return true, nil, nil, nil
			}
		case "product":
			if grant.ResourceID != "" {
				products[grant.ResourceID] = struct{}{}
			}
		case "project":
			if grant.ResourceID != "" {
				projects[grant.ResourceID] = struct{}{}
			}
		case "release":
			if grant.ResourceID != "" {
				releases[grant.ResourceID] = struct{}{}
			}
		}
	}
	return false, sortedSignatureIDs(products), sortedSignatureIDs(projects), sortedSignatureIDs(releases)
}

func signatureGrantHasScope(grant identitydomain.ResourceGrant) bool {
	for _, scope := range grant.Scopes {
		if scope == scopeSignatureRead || scope == "admin" || scope == "*" {
			return true
		}
	}
	return false
}

func sortedSignatureIDs(set map[string]struct{}) []string {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func hasSignatureCoordinate(ids []string, id string) bool {
	if id == "" {
		return false
	}
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}
