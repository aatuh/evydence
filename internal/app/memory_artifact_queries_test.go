package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type memoryArtifactQueryReader interface {
	releasequery.ArtifactPointReader
	ReadBuildArtifact(context.Context, string, string) (releasedomain.Artifact, error)
	ReadBuildArtifactGrant(context.Context, releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error)
}

func memoryArtifactQueryFixture(t *testing.T) (*memoryUnitOfWork, memoryArtifactQueryReader, domain.Artifact) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().ReleaseCatalog.(memoryArtifactQueryReader)
	if !ok {
		t.Fatal("memory catalog lacks focused artifact point/identity/grant readers")
	}
	a := domain.Artifact{ID: "artifact", TenantID: "tenant", Name: "Artifact", MediaType: "application/octet-stream", Size: 42, Digest: "sha256:" + strings.Repeat("a", 64), CreatedAt: fixedNow()}
	tx.state.Artifacts[a.ID] = a
	return tx, r, a
}

func TestMemoryArtifactQueriesReturnOwnedPointsAndMetadataFreeGuardProjections(t *testing.T) {
	tx, r, a := memoryArtifactQueryFixture(t)
	req := releasequery.ArtifactReadRequest{TenantID: "tenant", ID: a.ID, TenantWide: true}
	point, err := r.GetArtifactPoint(t.Context(), req)
	if err != nil || point != (releasequery.ArtifactPoint{Artifact: releasedomain.Artifact(a), Visible: true}) {
		t.Fatal("full artifact fields changed", point, err)
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"foreign", "missing"} {
		req.TenantID = tenant
		if v, err := r.GetArtifactPoint(t.Context(), req); !errors.Is(err, releasequery.ErrNotFound) || v != (releasequery.ArtifactPoint{}) {
			t.Fatal("foreign artifact point exposed data", v, err)
		}
		if v, err := r.ReadBuildArtifact(t.Context(), tenant, a.ID); !errors.Is(err, ErrNotFound) || v != (releasedomain.Artifact{}) {
			t.Fatal("foreign artifact identity exposed data", v, err)
		}
	}
	req.TenantID = "tenant"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("point reads changed stored state")
	}
	a.Name, a.MediaType, a.Size = strings.Repeat("private", 10000), strings.Repeat("private", 10000), -1
	tx.state.Artifacts[a.ID] = a
	if v, err := r.GetArtifactPoint(t.Context(), req); !errors.Is(err, releasequery.ErrInvalidProjection) || v != (releasequery.ArtifactPoint{}) {
		t.Fatal("corrupt selected metadata returned partial point", v, err)
	}
	wantIdentity := releasedomain.Artifact{ID: a.ID, TenantID: a.TenantID, Digest: a.Digest}
	if v, err := r.ReadBuildArtifact(t.Context(), "tenant", a.ID); err != nil || v != wantIdentity {
		t.Fatal("identity read selected unrelated metadata", v, err)
	}
	wantGrant := releasequery.ArtifactPoint{Artifact: releasedomain.Artifact{ID: a.ID, TenantID: a.TenantID, CreatedAt: a.CreatedAt}, Visible: true}
	if v, err := r.ReadBuildArtifactGrant(t.Context(), req); err != nil || v != wantGrant {
		t.Fatal("grant read selected digest/descriptive metadata", v, err)
	}
	a.Digest = strings.Repeat("x", 72)
	tx.state.Artifacts[a.ID] = a
	if v, err := r.ReadBuildArtifact(t.Context(), "tenant", a.ID); !errors.Is(err, ErrConflict) || v != (releasedomain.Artifact{}) {
		t.Fatal("oversized selected digest returned identity", v, err)
	}
	if v, err := r.ReadBuildArtifactGrant(t.Context(), req); err != nil || v != wantGrant {
		t.Fatal("tenant-wide grant decoded an unselected digest", v, err)
	}
}

func TestMemoryArtifactVisibilityUsesCurrentCoherentEvidenceAndDigestMatchedBuildAssociations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*MemoryUnitOfWorkSnapshot, *releasequery.ArtifactReadRequest)
		visible bool
	}{
		{"evidence-product", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			r.AllowedProductIDs = []string{"tenant-product"}
		}, true},
		{"evidence-project", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			r.AllowedProjectIDs = []string{"tenant-project"}
		}, true},
		{"evidence-release", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			r.AllowedReleaseIDs = []string{"tenant-release"}
		}, true},
		{"no-derived-evidence-grant", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			v := s.Evidence["ref"]
			v.ProductID, v.ReleaseID = "", ""
			s.Evidence[v.ID] = v
			r.AllowedProductIDs = []string{"tenant-product"}
		}, false},
		{"ungranted", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			r.AllowedProductIDs = []string{"ungranted"}
		}, false},
		{"foreign-evidence", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			v := s.Evidence["ref"]
			v.TenantID = "foreign"
			s.Evidence[v.ID] = v
			r.AllowedProductIDs = []string{"tenant-product"}
		}, false},
		{"foreign-parent", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			v := s.Projects["tenant-project"]
			v.TenantID = "foreign"
			s.Projects[v.ID] = v
			r.AllowedProductIDs = []string{"tenant-product"}
		}, false},
		{"dangling-parent", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			delete(s.Releases, "tenant-release")
			r.AllowedProductIDs = []string{"tenant-product"}
		}, false},
		{"cross-product", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			v := s.Projects["tenant-project"]
			v.ProductID = "other"
			s.Projects[v.ID] = v
			r.AllowedProductIDs = []string{"tenant-product"}
		}, false},
		{"wrong-reference-type", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			v := s.Evidence["ref"]
			v.SubjectRefs[0].Type = "build"
			s.Evidence[v.ID] = v
			r.AllowedProductIDs = []string{"tenant-product"}
		}, false},
		{"build-output", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			delete(s.Evidence, "ref")
			r.AllowedProductIDs = []string{"tenant-product"}
			s.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: "sha256:" + strings.Repeat("a", 64)}}}
		}, true},
		{"wrong-output-digest", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			delete(s.Evidence, "ref")
			r.AllowedProductIDs = []string{"tenant-product"}
			s.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: "sha256:" + strings.Repeat("b", 64)}}}
		}, false},
		{"foreign-build", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			delete(s.Evidence, "ref")
			r.AllowedProjectIDs = []string{"tenant-project"}
			s.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "foreign", ProjectID: "tenant-project", ReleaseID: "tenant-release", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: "sha256:" + strings.Repeat("a", 64)}}}
		}, false},
		{"cross-product-build", func(s *MemoryUnitOfWorkSnapshot, r *releasequery.ArtifactReadRequest) {
			delete(s.Evidence, "ref")
			r.AllowedProjectIDs = []string{"tenant-project"}
			v := s.Releases["tenant-release"]
			v.ProductID = "foreign-product"
			s.Releases[v.ID] = v
			s.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: "sha256:" + strings.Repeat("a", 64)}}}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, reader, a := memoryArtifactQueryFixture(t)
			tx.state.Evidence["ref"] = domain.EvidenceItem{ID: "ref", TenantID: "tenant", ProductID: "tenant-product", ProjectID: "tenant-project", ReleaseID: "tenant-release", Title: strings.Repeat("private", 10000), SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: a.ID}}}
			req := releasequery.ArtifactReadRequest{TenantID: "tenant", ID: a.ID}
			tc.mutate(&tx.state, &req)
			point, err := reader.GetArtifactPoint(t.Context(), req)
			if err != nil || point.Artifact != releasedomain.Artifact(a) || point.Visible != tc.visible {
				t.Fatal("artifact point association mismatch", point, err)
			}
			grant, err := reader.ReadBuildArtifactGrant(t.Context(), req)
			if err != nil || grant != (releasequery.ArtifactPoint{Artifact: releasedomain.Artifact{ID: a.ID, TenantID: a.TenantID, CreatedAt: a.CreatedAt}, Visible: tc.visible}) {
				t.Fatal("artifact grant selected metadata or used different association", grant, err)
			}
		})
	}
}

func TestMemoryArtifactQueriesRejectInvalidRequestsCancellationAndClosedTransactions(t *testing.T) {
	tx, r, a := memoryArtifactQueryFixture(t)
	req := releasequery.ArtifactReadRequest{TenantID: "tenant", ID: a.ID, TenantWide: true}
	for _, invalid := range []releasequery.ArtifactReadRequest{{TenantID: "tenant", ID: a.ID}, {TenantID: "tenant", ID: a.ID, TenantWide: true, AllowedProductIDs: []string{"tenant-product"}}, {TenantID: "tenant", ID: a.ID, AllowedProjectIDs: []string{" bad"}}} {
		if v, err := r.GetArtifactPoint(t.Context(), invalid); !errors.Is(err, releasequery.ErrValidation) || v != (releasequery.ArtifactPoint{}) {
			t.Fatal("contradictory/invalid visibility returned point", v, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var absent context.Context
	for _, check := range []struct {
		ctx  context.Context
		want error
	}{{ctx, context.Canceled}, {absent, releasequery.ErrValidation}} {
		if v, err := r.GetArtifactPoint(check.ctx, req); !errors.Is(err, check.want) || v != (releasequery.ArtifactPoint{}) {
			t.Fatal("invalid context returned artifact point", v, err)
		}
		if v, err := r.ReadBuildArtifactGrant(check.ctx, req); !errors.Is(err, check.want) || v != (releasequery.ArtifactPoint{}) {
			t.Fatal("invalid context returned artifact grant", v, err)
		}
	}
	if v, err := r.ReadBuildArtifact(ctx, "tenant", a.ID); !errors.Is(err, context.Canceled) || v != (releasedomain.Artifact{}) {
		t.Fatal("cancelled identity returned data", v, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v, err := r.GetArtifactPoint(t.Context(), req); !errors.Is(err, ErrConflict) || v != (releasequery.ArtifactPoint{}) {
		t.Fatal("closed transaction returned point", v, err)
	}
	if v, err := r.ReadBuildArtifactGrant(t.Context(), req); !errors.Is(err, ErrConflict) || v != (releasequery.ArtifactPoint{}) {
		t.Fatal("closed transaction returned grant", v, err)
	}
	if v, err := r.ReadBuildArtifact(t.Context(), "tenant", a.ID); !errors.Is(err, ErrConflict) || v != (releasedomain.Artifact{}) {
		t.Fatal("closed transaction returned identity", v, err)
	}
}
