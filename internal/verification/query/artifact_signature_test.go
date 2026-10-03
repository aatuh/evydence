package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type signatureReaderStub struct {
	request SignatureReadRequest
	point   SignaturePoint
	calls   int
}

func (r *signatureReaderStub) GetArtifactSignaturePoint(_ context.Context, request SignatureReadRequest) (SignaturePoint, error) {
	r.calls++
	r.request = request
	return r.point, nil
}

func TestArtifactSignatureQueryAuthorizesCurrentAssociation(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	reader := &signatureReaderStub{point: SignaturePoint{
		Signature:      verificationdomain.ArtifactSignature{ID: "sig_1", TenantID: "ten_1", ArtifactID: "art_1", SubjectDigest: "sha256:subject", Algorithm: "ed25519", Signature: "signed", VerificationStatus: "recorded", SchemaVersion: verificationdomain.ArtifactSignatureSchemaVersion, CreatedAt: now},
		ArtifactDigest: "sha256:subject", ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1",
	}}
	service, err := NewArtifactSignatures(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "prod_1", Scopes: []string{"evidence:read"}}}}
	sig, err := service.GetArtifactSignature(t.Context(), actor, "sig_1")
	if err != nil || sig.ID != "sig_1" || reader.request.TenantWide || len(reader.request.AllowedProductIDs) != 1 || reader.request.AllowedProductIDs[0] != "prod_1" {
		t.Fatalf("authorized signature=%#v request=%#v error=%v", sig, reader.request, err)
	}
	actor.ResourceGrants[0].ResourceID = "prod_other"
	if _, err := service.GetArtifactSignature(t.Context(), actor, "sig_1"); !errors.Is(err, ErrSignatureProjection) {
		t.Fatalf("widened product projection error=%v", err)
	}
	reader.point.ProductID, reader.point.ProjectID, reader.point.ReleaseID = "", "", ""
	if _, err := service.GetArtifactSignature(t.Context(), actor, "sig_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("unassociated signature error=%v", err)
	}
	actor.ResourceGrants[0] = identitydomain.ResourceGrant{ResourceType: "tenant", ResourceID: actor.TenantID, Scopes: []string{"evidence:read"}}
	if _, err := service.GetArtifactSignature(t.Context(), actor, "sig_1"); err != nil || !reader.request.TenantWide {
		t.Fatalf("tenant-granted signature request=%#v error=%v", reader.request, err)
	}
	actor = identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"evidence:read"}}
	if _, err := service.GetArtifactSignature(t.Context(), actor, "sig_1"); err != nil || !reader.request.TenantWide {
		t.Fatalf("credential signature request=%#v error=%v", reader.request, err)
	}
}

func TestArtifactSignatureQueryRejectsInvalidActorAndProjection(t *testing.T) {
	reader := &signatureReaderStub{}
	service, err := NewArtifactSignatures(reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"evidence:read"}}
	if _, err := service.GetArtifactSignature(t.Context(), actor, " "); !errors.Is(err, ErrSignatureNotFound) {
		t.Fatalf("blank id error=%v", err)
	}
	actor.Scopes = nil
	if _, err := service.GetArtifactSignature(t.Context(), actor, "sig_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("missing scope error=%v", err)
	}
	actor.KeyID = ""
	if _, err := service.GetArtifactSignature(t.Context(), actor, "sig_1"); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatalf("missing identity error=%v", err)
	}
	if reader.calls != 0 {
		t.Fatalf("invalid requests reached reader %d times", reader.calls)
	}
	actor.KeyID = "key_1"
	actor.Scopes = []string{"evidence:read"}
	reader.point = SignaturePoint{Signature: verificationdomain.ArtifactSignature{ID: "sig_1", TenantID: "ten_other", ArtifactID: "art_1", SubjectDigest: "sha256:a", CreatedAt: time.Now()}, ArtifactDigest: "sha256:a"}
	if _, err := service.GetArtifactSignature(t.Context(), actor, "sig_1"); !errors.Is(err, ErrSignatureProjection) {
		t.Fatalf("cross-tenant projection error=%v", err)
	}
}
