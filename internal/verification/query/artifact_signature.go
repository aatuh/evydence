package query

import (
	"context"
	"errors"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

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
	visibility, err := authz.ReadVisibility(ctx, actor, authz.ActionArtifactSignaturesRead)
	if err != nil {
		return verificationdomain.ArtifactSignature{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return verificationdomain.ArtifactSignature{}, ErrSignatureNotFound
	}
	tenantWide, products, projects, releases := visibility.TenantWide, visibility.ProductIDs, visibility.ProjectIDs, visibility.ReleaseIDs
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
	if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionArtifactSignaturesRead, Resources: authz.ResourceReferences{ProductID: point.ProductID, ProjectID: point.ProjectID, ReleaseID: point.ReleaseID}}); err != nil {
		return verificationdomain.ArtifactSignature{}, err
	}
	return signature, nil
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
