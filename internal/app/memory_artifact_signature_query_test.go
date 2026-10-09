package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func memoryArtifactSignatureFixture(t *testing.T) (*memoryUnitOfWork, verificationquery.ArtifactSignatureReader, domain.ArtifactSignature) {
	t.Helper()
	tx, _, artifact := memoryArtifactQueryFixture(t)
	reader, ok := tx.Repositories().ReleaseCatalog.(verificationquery.ArtifactSignatureReader)
	if !ok {
		t.Fatal("memory catalog lacks native artifact-signature point reader")
	}
	signature := domain.ArtifactSignature{ID: "signature", TenantID: "tenant", ArtifactID: artifact.ID, SubjectDigest: artifact.Digest, Algorithm: "cosign", KeyID: "public-key", Signature: "recorded-signature", PayloadRef: "object://public-reference", PayloadHash: "recorded-digest", VerificationStatus: "recorded", SchemaVersion: "1", CreatedAt: fixedNow()}
	tx.state.ArtifactSignatures[signature.ID] = signature
	tx.state.Evidence["ref"] = domain.EvidenceItem{ID: "ref", TenantID: "tenant", ProductID: "tenant-product", ProjectID: "tenant-project", ReleaseID: "tenant-release", SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: artifact.ID}}}
	return tx, reader, signature
}

func TestMemoryArtifactSignaturePointRetainsPublicFieldsWithoutReadingUnrelatedMetadata(t *testing.T) {
	tx, reader, signature := memoryArtifactSignatureFixture(t)
	a := tx.state.Artifacts[signature.ArtifactID]
	a.Name, a.MediaType, a.Size = strings.Repeat("unselected", 10000), strings.Repeat("unselected", 10000), -1
	tx.state.Artifacts[a.ID] = a
	tx.state.SigningKeys["private"] = domain.SigningKey{Private: []byte(strings.Repeat("private-key", 100000))}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []verificationquery.SignatureReadRequest{
		{TenantID: "tenant", ID: signature.ID, TenantWide: true},
		{TenantID: "tenant", ID: signature.ID, AllowedProductIDs: []string{"tenant-product"}},
		{TenantID: "tenant", ID: signature.ID, AllowedProjectIDs: []string{"tenant-project"}},
		{TenantID: "tenant", ID: signature.ID, AllowedReleaseIDs: []string{"tenant-release"}},
	} {
		v, err := reader.GetArtifactSignaturePoint(t.Context(), request)
		if err != nil || v.Signature != verificationdomain.ArtifactSignature(signature) || v.ArtifactDigest != signature.SubjectDigest {
			t.Fatal("native point lost public fields or consulted unrelated metadata", err)
		}
		if !request.TenantWide && (v.ProductID != "tenant-product" || v.ProjectID != "tenant-project" || v.ReleaseID != "tenant-release") {
			t.Fatal("native association lost explicit authorized coordinates", v)
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("signature point reads changed repository state")
	}
}

func TestMemoryArtifactSignatureQueryUsesCurrentCoherentEvidenceAndDigestBoundBuilds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*MemoryUnitOfWorkSnapshot)
		want   error
	}{
		{"owned evidence", func(*MemoryUnitOfWorkSnapshot) {}, nil},
		{"removed evidence", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Evidence, "ref") }, application.ErrForbidden},
		{"foreign evidence", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["ref"]
			v.TenantID = "foreign"
			s.Evidence[v.ID] = v
		}, application.ErrForbidden},
		{"foreign project", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Projects["tenant-project"]
			v.TenantID = "foreign"
			s.Projects[v.ID] = v
		}, application.ErrForbidden},
		{"missing release", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Releases, "tenant-release") }, application.ErrForbidden},
		{"cross product", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Releases["tenant-release"]
			v.ProductID = "other"
			s.Releases[v.ID] = v
		}, application.ErrForbidden},
		{"foreign signature", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.ArtifactSignatures["signature"]
			v.TenantID = "foreign"
			s.ArtifactSignatures[v.ID] = v
		}, verificationquery.ErrSignatureNotFound},
		{"foreign artifact", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Artifacts["artifact"]
			v.TenantID = "foreign"
			s.Artifacts[v.ID] = v
		}, verificationquery.ErrSignatureNotFound},
		{"missing artifact", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Artifacts, "artifact") }, verificationquery.ErrSignatureNotFound},
		{"wrong digest", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Artifacts["artifact"]
			v.Digest = "changed"
			s.Artifacts[v.ID] = v
		}, verificationquery.ErrSignatureNotFound},
		{"owned build", func(s *MemoryUnitOfWorkSnapshot) {
			delete(s.Evidence, "ref")
			s.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: s.Artifacts["artifact"].Digest}}}
		}, nil},
		{"wrong build digest", func(s *MemoryUnitOfWorkSnapshot) {
			delete(s.Evidence, "ref")
			s.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: "wrong"}}}
		}, application.ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, reader, signature := memoryArtifactSignatureFixture(t)
			tc.mutate(&tx.state)
			query, err := verificationquery.NewArtifactSignatures(reader)
			if err != nil {
				t.Fatal(err)
			}
			actor := domain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"evidence:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "tenant-product", Scopes: []string{"evidence:read"}}}}
			v, err := query.GetArtifactSignature(t.Context(), actor, signature.ID)
			if tc.want == nil {
				if err != nil || v != verificationdomain.ArtifactSignature(signature) {
					t.Fatal("owned signature association was denied or changed", err)
				}
			} else if !errors.Is(err, tc.want) || v != (verificationdomain.ArtifactSignature{}) {
				t.Fatal("foreign/stale signature association exposed data or wrong error", err)
			}
		})
	}
}

func TestMemoryArtifactSignaturePointRejectsInvalidRequestsAndClosedTransactions(t *testing.T) {
	tx, reader, signature := memoryArtifactSignatureFixture(t)
	request := verificationquery.SignatureReadRequest{TenantID: "tenant", ID: signature.ID, TenantWide: true}
	bad := request
	bad.AllowedProductIDs = []string{"tenant-product"}
	if _, err := reader.GetArtifactSignaturePoint(t.Context(), bad); err == nil {
		t.Fatal("mixed tenant-wide and scoped visibility accepted")
	}
	var missingContext context.Context
	if _, err := reader.GetArtifactSignaturePoint(missingContext, request); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.GetArtifactSignaturePoint(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not propagated", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.GetArtifactSignaturePoint(t.Context(), request); err == nil {
		t.Fatal("closed transaction returned a signature")
	}
}
