package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func memoryCustomerVerificationFixture(t *testing.T) *memoryUnitOfWork {
	t.Helper()
	tx := memoryCustomerProvenanceFixture(t)
	s := &tx.state
	s.ReleaseBundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "tenant-release", State: "draft", ManifestHash: "sha256:bundle", CreatedAt: fixedNow()}
	s.ArtifactSignatures["artifact-signature"] = domain.ArtifactSignature{ID: "artifact-signature", TenantID: "tenant", ArtifactID: "artifact-build", SubjectDigest: "sha256:artifact-build"}
	profile := domain.VerificationProfile{ID: "recorded-profile", Version: "1", RequiredChecks: []string{"signature"}, TrustMaterial: []string{"public trust"}, Limitations: []string{"recorded only"}}
	for _, subject := range []struct{ kind, id string }{{"release_bundle", "bundle"}, {"evidence_item", "selected"}, {"artifact_signature", "artifact-signature"}, {"build_attestation", "attestation"}} {
		v := domain.VerificationResult{ID: subject.kind + "-receipt", TenantID: "tenant", SubjectType: subject.kind, SubjectID: subject.id, Result: "failed", Checks: []domain.VerifyCheck{{Name: "z", Result: "failed", Detail: "recorded"}, {Name: "a", Result: "passed"}}, Profile: profile, Limitations: []string{"not a fresh check"}, SchemaVersion: "verification-result.v1", VerifiedAt: fixedNow()}
		s.VerificationResults[v.ID] = v
		v.ID, v.TenantID = "foreign-"+v.ID, "foreign"
		s.VerificationResults[v.ID] = v
	}
	v := s.VerificationResults["evidence_item-receipt"]
	v.ID, v.SubjectID = "sibling-receipt", "bad-project"
	s.VerificationResults[v.ID] = v
	s.ContainerImages["image"] = domain.ContainerImage{ID: "image", TenantID: "tenant", ArtifactID: "artifact-build", Digest: "sha256:artifact-build"}
	s.CosignVerifications["cosign"] = domain.CosignVerification{ID: "cosign", TenantID: "tenant", ArtifactID: "artifact-build", ArtifactSignatureID: "artifact-signature", ContainerImageID: "image", SubjectDigest: "sha256:artifact-build", Result: "unsupported", Profile: profile, Checks: []domain.VerifyCheck{{Name: "signature", Result: "unsupported"}}, Limitations: []string{"no live provider"}, RekorUUID: "private-rekor-marker", CertificateIdentity: "private-identity-marker", CreatedAt: fixedNow()}
	return tx
}

func TestMemoryCustomerPackageVerificationProjectsRecordedScopedReceiptsWithoutUpgradingTrust(t *testing.T) {
	tx := memoryCustomerVerificationFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	v, err := readMemoryCustomerPackageVerification(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
	if err != nil {
		t.Fatal(err)
	}
	results := v["verification_results"].([]map[string]any)
	if len(results) != 4 || len(v["release_bundles"].([]map[string]any)) != 1 || len(v["cosign_assessments"].([]map[string]any)) != 1 || v["hash_algorithm"] != "sha256" {
		t.Fatal("verification inventory or public shape changed", v)
	}
	for _, row := range results {
		if row["result"] != "failed" {
			t.Fatal("recorded failure was upgraded", row)
		}
		checks := row["checks"].([]map[string]any)
		if len(checks) != 2 || checks[0]["name"] != "a" || row["profile"].(domain.VerificationProfile).RequiredChecks[0] != "signature" {
			t.Fatal("recorded check/profile shape changed", row)
		}
	}
	if v["cosign_assessments"].([]map[string]any)[0]["result"] != "unsupported" {
		t.Fatal("recorded cosign result upgraded")
	}
	raw, err := json.Marshal(v)
	if err != nil || strings.Contains(string(raw), "private-") || strings.Contains(string(raw), "foreign-") || strings.Contains(string(raw), "sibling-receipt") {
		t.Fatal("private or unowned verification metadata projected", err)
	}
	results[0]["profile"].(domain.VerificationProfile).RequiredChecks[0] = "changed"
	results[0]["limitations"].([]string)[0] = "changed"
	results[0]["checks"].([]map[string]any)[0]["detail"] = "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("read/caller mutation changed stored receipts")
	}
}

func TestMemoryCustomerPackageVerificationRechecksSubjectsAndBoundsMetadata(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*MemoryUnitOfWorkSnapshot)
	}{
		{"cosign digest", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.CosignVerifications["cosign"]
			v.SubjectDigest = "sha256:wrong"
			s.CosignVerifications[v.ID] = v
		}},
		{"cosign image", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.ContainerImages["image"]
			v.TenantID = "foreign"
			s.ContainerImages[v.ID] = v
		}},
		{"cosign signature", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.ArtifactSignatures["artifact-signature"]
			v.TenantID = "foreign"
			s.ArtifactSignatures[v.ID] = v
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerVerificationFixture(t)
			change.edit(&tx.state)
			v, err := readMemoryCustomerPackageVerification(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes})
			if err != nil || len(v["cosign_assessments"].([]map[string]any)) != 0 {
				t.Fatal("incoherent cosign receipt selected", v, err)
			}
		})
	}
	for _, change := range []struct {
		name string
		edit func(*domain.VerificationResult)
	}{{"checks", func(v *domain.VerificationResult) { v.Checks = make([]domain.VerifyCheck, 4097) }}, {"profile", func(v *domain.VerificationResult) { v.Profile.TrustMaterial = make([]string, 4097) }}, {"text", func(v *domain.VerificationResult) {
		v.Limitations = []string{strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes+1)}
	}}} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerVerificationFixture(t)
			r := tx.state.VerificationResults["evidence_item-receipt"]
			change.edit(&r)
			tx.state.VerificationResults[r.ID] = r
			b := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
			v, err := readMemoryCustomerPackageVerification(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", b)
			if !errors.Is(err, ErrConflict) || v != nil || b.remainingBytes != packageapp.MaxCustomerPackageManifestBytes {
				t.Fatal("partial invalid verification metadata published", err)
			}
		})
	}
	tx := memoryCustomerVerificationFixture(t)
	b := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	if _, err := readMemoryCustomerPackageVerification(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", b); err != nil {
		t.Fatal(err)
	}
	used := packageapp.MaxCustomerPackageManifestBytes - b.remainingBytes
	short := &memoryCustomerSnapshotBudget{remainingBytes: used - 1}
	if v, err := readMemoryCustomerPackageVerification(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", short); !errors.Is(err, ErrConflict) || v != nil || short.remainingBytes != used-1 {
		t.Fatal("combined verification budget bypassed", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readMemoryCustomerPackageVerification(ctx, &tx.state, "tenant", "tenant-product", "tenant-release", b); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("cancelled verification metadata returned", err)
	}
}
