package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func memoryCustomerProvenanceProfile() packagedomain.RedactionProfile {
	return packagedomain.RedactionProfile{ID: "profile", TenantID: "tenant", AllowedTypes: []string{"build", "build_attestation"}}
}

func memoryCustomerProvenanceFixture(t *testing.T) *memoryUnitOfWork {
	t.Helper()
	tx := memoryCustomerCatalogFixture(t)
	s := &tx.state
	b := s.BuildRuns["build"]
	b.CollectorID, b.Provider, b.CommitSHA, b.Repository, b.WorkflowRef, b.RunID, b.RunAttempt = "tenant-collector", "CI", "commit", "repository", "workflow", "run", 2
	b.Status, b.StartedAt, b.CreatedAt, b.SchemaVersion = "passed", fixedNow(), fixedNow(), "build.v1"
	b.ParametersHash, b.EnvironmentHash = "sha256:parameters", "sha256:environment"
	b.Actor, b.OIDCSubject, b.JobID = "private-actor-marker", "private-oidc-marker", "private-job-marker"
	b.SourceIdentity = map[string]any{"token": "private-token-marker"}
	b.Outputs = []domain.BuildOutput{{ArtifactID: "artifact-build", Digest: "sha256:artifact-build"}, {Digest: "sha256:unregistered"}}
	s.BuildRuns[b.ID] = b
	for _, row := range []struct{ id, tenant, project, release string }{{"unreleased", "tenant", "tenant-project", ""}, {"unreleased-sibling", "tenant", "sibling-project", ""}, {"foreign-build", "foreign", "foreign-project", "foreign-release"}} {
		v := b
		v.ID, v.TenantID, v.ProjectID, v.ReleaseID, v.CollectorID, v.Outputs = row.id, row.tenant, row.project, row.release, "", nil
		s.BuildRuns[v.ID] = v
	}
	e := s.Evidence["selected"]
	e.ID, e.Type, e.BuildID, e.PayloadRef, e.PayloadHash, e.PayloadSize = "attestation-source", "build_attestation", "build", "private-payload-marker", "sha256:attestation", 7
	e.SubjectRefs = nil
	s.Evidence[e.ID] = e
	a := domain.BuildAttestation{ID: "attestation", TenantID: "tenant", BuildID: "build", EvidenceID: e.ID, PayloadRef: e.PayloadRef, PayloadHash: e.PayloadHash, PayloadSize: e.PayloadSize, PayloadType: "application/vnd.in-toto+json", PredicateType: "https://slsa.dev/provenance/v1", SubjectDigests: []string{"sha256:artifact-build"}, SignatureCount: 2, VerificationStatus: "structurally_valid", SchemaVersion: "attestation.v1", CreatedAt: fixedNow(), BuilderID: "private-builder-marker", BuildType: "private-build-type-marker"}
	s.BuildAttestations[a.ID] = a
	a.ID, a.TenantID = "foreign-attestation", "foreign"
	s.BuildAttestations[a.ID] = a
	a.ID, a.TenantID, a.EvidenceID = "wrong-source-attestation", "tenant", "foreign-evidence"
	s.BuildAttestations[a.ID] = a
	return tx
}

func TestMemoryCustomerPackageProvenancePreservesRecordedMetadataWithoutPrivateSources(t *testing.T) {
	tx := memoryCustomerProvenanceFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	v, err := readMemoryCustomerPackageProvenance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerProvenanceProfile(), &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	builds, attestations := v["builds"].([]map[string]any), v["build_attestations"].([]map[string]any)
	if len(builds) != 1 || builds[0]["id"] != "build" || len(attestations) != 1 || attestations[0]["id"] != "attestation" || builds[0]["run_attempt"] != 2 || builds[0]["collector_id"] != "tenant-collector" || builds[0]["finished_at"] != "" || builds[0]["started_at"] != fixedNow().UTC().Format(time.RFC3339) || attestations[0]["payload_size"] != int64(7) || attestations[0]["verification_status"] != "structurally_valid" {
		t.Fatal("provenance public fields/status changed", v)
	}
	if !reflect.DeepEqual(builds[0]["outputs"], []map[string]any{{"artifact_id": "", "digest": "sha256:unregistered"}, {"artifact_id": "artifact-build", "digest": "sha256:artifact-build"}}) || !reflect.DeepEqual(attestations[0]["subject_digests"], []string{"sha256:artifact-build"}) {
		t.Fatal("public output shapes/order changed", v)
	}
	raw, err := json.Marshal(v)
	if err != nil || strings.Contains(string(raw), "private-") || strings.Contains(string(raw), "payload_ref") || strings.Contains(string(raw), "source_identity") {
		t.Fatal("private provenance projected", err)
	}
	builds[0]["outputs"].([]map[string]any)[0]["digest"] = "changed"
	attestations[0]["subject_digests"].([]string)[0] = "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("read/caller mutation changed storage")
	}
	product, err := readMemoryCustomerPackageProvenance(t.Context(), &tx.state, "tenant", "tenant-product", "", memoryCustomerProvenanceProfile(), &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil || len(product["builds"].([]map[string]any)) != 1 || product["builds"].([]map[string]any)[0]["id"] != "unreleased" || len(product["build_attestations"].([]map[string]any)) != 0 {
		t.Fatal("product-only unreleased build policy changed", product, err)
	}
}

func TestMemoryCustomerPackageProvenanceHonorsTypesAndCurrentParentBindings(t *testing.T) {
	for _, tc := range []struct {
		types                []string
		builds, attestations int
	}{{nil, 0, 0}, {[]string{"build_attestation"}, 0, 0}, {[]string{"build"}, 1, 0}, {[]string{" build ", "build_attestation"}, 1, 1}} {
		tx := memoryCustomerProvenanceFixture(t)
		p := memoryCustomerProvenanceProfile()
		p.AllowedTypes = tc.types
		v, err := readMemoryCustomerPackageProvenance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", p, &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
		if err != nil || len(v["builds"].([]map[string]any)) != tc.builds || len(v["build_attestations"].([]map[string]any)) != tc.attestations {
			t.Fatal("type selection changed", tc.types, v, err)
		}
	}
	for _, change := range []struct {
		name   string
		builds int
		edit   func(*MemoryUnitOfWorkSnapshot)
	}{
		{"project", 0, func(s *MemoryUnitOfWorkSnapshot) {
			b := s.BuildRuns["build"]
			b.ProjectID = "sibling-project"
			s.BuildRuns[b.ID] = b
		}},
		{"collector", 0, func(s *MemoryUnitOfWorkSnapshot) {
			b := s.BuildRuns["build"]
			b.CollectorID = "foreign-collector"
			s.BuildRuns[b.ID] = b
		}},
		{"output tenant", 0, func(s *MemoryUnitOfWorkSnapshot) {
			b := s.BuildRuns["build"]
			b.Outputs = []domain.BuildOutput{{ArtifactID: "artifact-foreign", Digest: "sha256:artifact-foreign"}}
			s.BuildRuns[b.ID] = b
		}},
		{"output digest", 0, func(s *MemoryUnitOfWorkSnapshot) {
			b := s.BuildRuns["build"]
			b.Outputs = []domain.BuildOutput{{ArtifactID: "artifact-build", Digest: "sha256:wrong"}}
			s.BuildRuns[b.ID] = b
		}},
		{"source tenant", 1, func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["attestation-source"]
			e.TenantID = "foreign"
			s.Evidence[e.ID] = e
		}},
		{"source product", 1, func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["attestation-source"]
			e.ProductID = "sibling"
			s.Evidence[e.ID] = e
		}},
		{"source project", 1, func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["attestation-source"]
			e.ProjectID = "sibling-project"
			s.Evidence[e.ID] = e
		}},
		{"source release", 1, func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["attestation-source"]
			e.ReleaseID = "other-release"
			s.Evidence[e.ID] = e
		}},
		{"source build", 1, func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["attestation-source"]
			e.BuildID = "bad-build"
			s.Evidence[e.ID] = e
		}},
		{"source kind", 1, func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["attestation-source"]
			e.Type = "document"
			s.Evidence[e.ID] = e
		}},
		{"source hash", 1, func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["attestation-source"]
			e.PayloadHash = "sha256:wrong"
			s.Evidence[e.ID] = e
		}},
		{"source size", 1, func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["attestation-source"]
			e.PayloadSize = 8
			s.Evidence[e.ID] = e
		}},
		{"source storage", 1, func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["attestation-source"]
			e.PayloadRef = "private-other-marker"
			s.Evidence[e.ID] = e
		}},
		{"source deployment", 1, func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["attestation-source"]
			e.DeploymentID = "missing"
			s.Evidence[e.ID] = e
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerProvenanceFixture(t)
			change.edit(&tx.state)
			v, err := readMemoryCustomerPackageProvenance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerProvenanceProfile(), &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v["builds"].([]map[string]any)) != change.builds || len(v["build_attestations"].([]map[string]any)) != 0 {
				t.Fatal("incoherent provenance retained", v, err)
			}
		})
	}
}

func TestMemoryCustomerPackageProvenanceBoundsPublicFieldsAndSharesBudget(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*MemoryUnitOfWorkSnapshot)
	}{
		{"output count", func(s *MemoryUnitOfWorkSnapshot) {
			b := s.BuildRuns["build"]
			b.Outputs = make([]domain.BuildOutput, 4097)
			s.BuildRuns[b.ID] = b
		}},
		{"output bytes", func(s *MemoryUnitOfWorkSnapshot) {
			b := s.BuildRuns["build"]
			b.Outputs = []domain.BuildOutput{{Digest: strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)}}
			s.BuildRuns[b.ID] = b
		}},
		{"public bytes", func(s *MemoryUnitOfWorkSnapshot) {
			b := s.BuildRuns["build"]
			b.Repository = strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)
			s.BuildRuns[b.ID] = b
		}},
		{"subject count", func(s *MemoryUnitOfWorkSnapshot) {
			a := s.BuildAttestations["attestation"]
			a.SubjectDigests = make([]string, 4097)
			s.BuildAttestations[a.ID] = a
		}},
		{"signature count", func(s *MemoryUnitOfWorkSnapshot) {
			a := s.BuildAttestations["attestation"]
			a.SignatureCount = -1
			s.BuildAttestations[a.ID] = a
		}},
		{"time", func(s *MemoryUnitOfWorkSnapshot) {
			b := s.BuildRuns["build"]
			b.FinishedAt = timePtr(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
			s.BuildRuns[b.ID] = b
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerProvenanceFixture(t)
			change.edit(&tx.state)
			b := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readMemoryCustomerPackageProvenance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerProvenanceProfile(), b)
			if !errors.Is(err, ErrConflict) || v != nil || b.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
				t.Fatal("invalid provenance or partial budget published", err)
			}
		})
	}
	tx := memoryCustomerProvenanceFixture(t)
	baseline := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readMemoryCustomerPackageProvenance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerProvenanceProfile(), baseline); err != nil {
		t.Fatal(err)
	}
	used := packageapp.MaxCustomerPackageManifestBytes - baseline.remainingBytes
	b := &memoryCustomerSnapshotBudget{remainingBytes: used - 1}
	if v, err := readMemoryCustomerPackageProvenance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerProvenanceProfile(), b); !errors.Is(err, ErrConflict) || v != nil || b.remainingBytes != used-1 {
		t.Fatal("combined provenance sections exceeded budget", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readMemoryCustomerPackageProvenance(ctx, &tx.state, "tenant", "tenant-product", "tenant-release", memoryCustomerProvenanceProfile(), baseline); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("cancelled provenance returned", err)
	}
}

func TestMemoryCustomerPackageProvenanceRejectsForeignRootsAndPolicyBeforeReading(t *testing.T) {
	tx := memoryCustomerProvenanceFixture(t)
	for _, coordinates := range [][3]string{{"tenant", "foreign-product", ""}, {"foreign", "tenant-product", "tenant-release"}, {"tenant", "tenant-product", "sibling-release"}, {"unknown", "tenant-product", ""}} {
		p := memoryCustomerProvenanceProfile()
		p.TenantID = coordinates[0]
		b := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
		v, err := readMemoryCustomerPackageProvenance(t.Context(), &tx.state, coordinates[0], coordinates[1], coordinates[2], p, b)
		if !errors.Is(err, ErrNotFound) || v != nil || b.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
			t.Fatal("foreign roots returned provenance or spent budget", coordinates, err)
		}
	}
	p := memoryCustomerProvenanceProfile()
	p.TenantID = "foreign"
	if v, err := readMemoryCustomerPackageProvenance(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", p, &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, ErrValidation) || v != nil {
		t.Fatal("foreign policy selected provenance", err)
	}
	for _, id := range []string{" padded ", "\xff", "nul\x00", strings.Repeat("x", packageapp.MaxCustomerPackageIDBytes+1)} {
		if v, err := readMemoryCustomerPackageProvenance(t.Context(), &tx.state, "tenant", id, "tenant-release", memoryCustomerProvenanceProfile(), &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}); !errors.Is(err, ErrValidation) || v != nil {
			t.Fatal("invalid scope accepted", err)
		}
	}
}
