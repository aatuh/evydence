package app

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func memoryDSSEFixture(t *testing.T) (*memoryUnitOfWork, verificationapp.DSSEVerificationReader) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	staging, final, err := CanonicalObjectPayloadKeys("tenant", digest)
	if err != nil {
		t.Fatal(err)
	}
	tx.state.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: digest}}}
	tx.state.Artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: "tenant", Digest: digest}
	e := domain.EvidenceItem{ID: "source", TenantID: "tenant", ProductID: "tenant-product", ProjectID: "tenant-project", ReleaseID: "tenant-release", BuildID: "build", Type: "build_attestation", PayloadRef: "object://" + final, PayloadHash: digest, PayloadSize: 42, PayloadMediaType: "application/vnd.dsse.envelope+json"}
	tx.state.Evidence[e.ID] = e
	tx.state.Evidence["artifact-link"] = domain.EvidenceItem{ID: "artifact-link", TenantID: "tenant", ReleaseID: "tenant-release", SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: "artifact"}}}
	tx.state.BuildAttestations["attestation"] = domain.BuildAttestation{ID: "attestation", TenantID: "tenant", BuildID: "build", EvidenceID: e.ID, PayloadRef: e.PayloadRef, PayloadHash: e.PayloadHash, PayloadSize: e.PayloadSize, PayloadType: "application/vnd.in-toto+json", PredicateType: "https://slsa.dev/provenance/v1", SubjectDigests: []string{"sha256:" + strings.Repeat("b", 64)}, VerificationStatus: "structurally_valid", SchemaVersion: "attestation.v1", CreatedAt: fixedNow()}
	tx.state.ObjectPayloads[memoryObjectPayloadKey("tenant", digest)] = ObjectPayload{TenantID: "tenant", Digest: digest, Size: 42, MediaType: e.PayloadMediaType, StagingKey: staging, FinalKey: final, Status: ObjectPayloadFinalized, CreatedAt: fixedNow(), UpdatedAt: fixedNow()}
	tx.state.DSSETrustRoots["root"] = domain.DSSETrustRoot{ID: "root", TenantID: "tenant", Name: "Root", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Status: "active", SchemaVersion: domain.DSSETrustRootSchemaVersion, CreatedAt: fixedNow(), AllowedPredicateTypes: []string{"https://slsa.dev/provenance/v1"}, ExpectedBuilderIDs: []string{"builder"}, RequiredClaims: []string{"builder_id"}}
	r, ok := tx.Repositories().Verification.(verificationapp.DSSEVerificationReader)
	if !ok {
		t.Fatal("memory verification lacks focused DSSE reader")
	}
	return tx, r
}

func TestMemoryDSSEVerificationReadsCurrentRegisteredFactsAndDetachedRoots(t *testing.T) {
	tx, r := memoryDSSEFixture(t)
	subject, err := r.ResolveDSSEVerificationSubject(t.Context(), "tenant", "attestation")
	if err != nil || subject.Resources.ProductID != "tenant-product" || subject.Resources.BuildID != "build" {
		t.Fatal("current attestation ownership lost", subject, err)
	}
	v, err := r.ReadDSSEVerification(t.Context(), subject)
	if err != nil || v.Subject != subject || !v.PayloadFinalized || v.PayloadSize != 42 || len(v.Roots) != 1 || !reflect.DeepEqual(v.ExpectedSubjectDigests, []string{tx.state.Artifacts["artifact"].Digest}) {
		t.Fatal("registered digests replaced by parsed claims or current facts lost", err)
	}
	v.Roots[0].ExpectedBuilderIDs[0] = "caller"
	if tx.state.DSSETrustRoots["root"].ExpectedBuilderIDs[0] != "builder" {
		t.Fatal("DSSE root policy aliases repository")
	}
	delete(tx.state.Evidence, "artifact-link")
	v, err = r.ReadDSSEVerification(t.Context(), subject)
	if err != nil || len(v.ExpectedSubjectDigests) != 0 {
		t.Fatal("unlinked build output became trusted expected digest", err)
	}
	// Replay resolves only ownership, not selected/private inspection facts.
	a := tx.state.BuildAttestations["attestation"]
	a.PayloadRef = strings.Repeat("private", verificationapp.MaxDSSEVerificationBytes)
	tx.state.BuildAttestations[a.ID] = a
	b := tx.state.BuildRuns["build"]
	b.Outputs = make([]domain.BuildOutput, verificationapp.MaxDSSEVerificationRecords+1)
	tx.state.BuildRuns[b.ID] = b
	delete(tx.state.ObjectPayloads, memoryObjectPayloadKey("tenant", a.PayloadHash))
	if got, err := r.ResolveDSSEVerificationSubject(t.Context(), "tenant", a.ID); err != nil || got != subject {
		t.Fatal("ownership guard inspected mutable payload/output facts", err)
	}
}

func TestMemoryPayloadFinalizationPreservesRecordedBinding(t *testing.T) {
	tx, _ := memoryDSSEFixture(t)
	r, ok := tx.Repositories().Payloads.(interface {
		GetObjectPayload(context.Context, string, string) (ObjectPayload, error)
		MarkObjectPayloadFinalized(context.Context, ObjectPayload) error
	})
	if !ok {
		t.Fatal("memory payload repository lacks focused lifecycle transition")
	}
	digest := tx.state.BuildAttestations["attestation"].PayloadHash
	p, err := r.GetObjectPayload(t.Context(), "tenant", digest)
	if err != nil {
		t.Fatal(err)
	}
	p.Status = ObjectPayloadStaged
	tx.state.ObjectPayloads[memoryObjectPayloadKey("tenant", digest)] = p
	wrong := p
	wrong.Size++
	if err := r.MarkObjectPayloadFinalized(t.Context(), wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("finalization changed immutable payload size", err)
	}
	if err := r.MarkObjectPayloadFinalized(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetObjectPayload(t.Context(), "tenant", digest)
	if err != nil || got.Status != ObjectPayloadFinalized || got.Size != p.Size || got.Digest != p.Digest {
		t.Fatal("finalization lost immutable binding", err)
	}
	if _, err := r.GetObjectPayload(t.Context(), "foreign", digest); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign payload read accepted", err)
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.MarkObjectPayloadFinalized(t.Context(), p); err != nil || !reflect.DeepEqual(before, tx.state) {
		t.Fatal("repeat finalization changed metadata", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.GetObjectPayload(ctx, "tenant", digest); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, ObjectPayload{}) {
		t.Fatal("cancelled payload read exposed metadata", err)
	}
}

func TestMemorySubjectVerificationScopeUsesOnlyCurrentOwnedCoordinates(t *testing.T) {
	tx, _ := memoryDSSEFixture(t)
	r, ok := tx.Repositories().Verification.(verificationapp.SubjectVerificationScopeReader)
	if !ok {
		t.Fatal("memory verification lacks current replay scope reader")
	}
	tx.state.MerkleBatches["batch"] = domain.MerkleBatch{ID: "batch", TenantID: "tenant", RootHash: strings.Repeat("private", 100000)}
	tx.state.BackupManifests["backup"] = domain.BackupManifest{ID: "backup", TenantID: "tenant", StateHash: strings.Repeat("private", 100000)}
	tx.state.EvidenceBundles["bundle"] = domain.EvidenceBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "tenant-release", Manifest: map[string]any{"unreadable": func() {}}}
	for _, tc := range []struct{ kind, id, release string }{{"audit_chain", "", ""}, {"audit_chain_checkpoint", "batch", ""}, {"merkle_batch", "batch", ""}, {"backup_manifest", "backup", ""}, {"audit_chain_release_manifest", "bundle", ""}, {"release_bundle", "bundle", "tenant-release"}, {"build_attestation", "attestation", "tenant-release"}} {
		v, err := r.ResolveSubjectVerificationScope(t.Context(), "tenant", tc.kind, tc.id)
		if err != nil || v.ID != tc.id || v.Resources.ReleaseID != tc.release {
			t.Fatal("replay scope inspected private facts or lost current identity", tc.kind, err)
		}
		if tc.id != "" {
			if v, err := r.ResolveSubjectVerificationScope(t.Context(), "foreign", tc.kind, tc.id); !errors.Is(err, ErrNotFound) || v != (verificationapp.SubjectReference{}) {
				t.Fatal("foreign replay scope exposed", tc.kind, err)
			}
		}
	}
	delete(tx.state.Releases, "tenant-release")
	if v, err := r.ResolveSubjectVerificationScope(t.Context(), "tenant", "audit_chain_release_manifest", "bundle"); err == nil || v != (verificationapp.SubjectReference{}) {
		t.Fatal("missing current bundle parent authorized", err)
	}
}

func TestMemoryDSSEVerificationRejectsIncoherenceBoundsAndCancellationWithoutPartialFacts(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*MemoryUnitOfWorkSnapshot)
	}{
		{"foreign-source", func(s *MemoryUnitOfWorkSnapshot) {
			e := s.Evidence["source"]
			e.TenantID = "foreign"
			s.Evidence[e.ID] = e
		}},
		{"wrong-build", func(s *MemoryUnitOfWorkSnapshot) {
			a := s.BuildAttestations["attestation"]
			a.BuildID = "missing"
			s.BuildAttestations[a.ID] = a
		}},
		{"payload-size", func(s *MemoryUnitOfWorkSnapshot) {
			a := s.BuildAttestations["attestation"]
			a.PayloadSize++
			s.BuildAttestations[a.ID] = a
		}},
		{"unfinalized", func(s *MemoryUnitOfWorkSnapshot) {
			for key, p := range s.ObjectPayloads {
				p.Status = ObjectPayloadStaged
				s.ObjectPayloads[key] = p
			}
		}},
		{"foreign-payload", func(s *MemoryUnitOfWorkSnapshot) {
			for key, p := range s.ObjectPayloads {
				p.TenantID = "foreign"
				s.ObjectPayloads[key] = p
			}
		}},
		{"root-count", func(s *MemoryUnitOfWorkSnapshot) {
			root := s.DSSETrustRoots["root"]
			root.RequiredClaims = make([]string, verificationapp.MaxDSSEVerificationRecords+1)
			s.DSSETrustRoots[root.ID] = root
		}},
		{"root-bytes", func(s *MemoryUnitOfWorkSnapshot) {
			root := s.DSSETrustRoots["root"]
			root.Name = strings.Repeat("x", verificationapp.MaxDSSEVerificationBytes+1)
			s.DSSETrustRoots[root.ID] = root
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			tx, r := memoryDSSEFixture(t)
			subject, err := r.ResolveDSSEVerificationSubject(t.Context(), "tenant", "attestation")
			if err != nil {
				t.Fatal(err)
			}
			change.edit(&tx.state)
			v, err := r.ReadDSSEVerification(t.Context(), subject)
			if err == nil || !reflect.DeepEqual(v, verificationapp.DSSEVerificationSnapshot{}) {
				t.Fatal("invalid DSSE snapshot exposed partial facts", err)
			}
		})
	}
	_, r := memoryDSSEFixture(t)
	if _, err := r.ResolveDSSEVerificationSubject(t.Context(), "foreign", "attestation"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign attestation resolved", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.ResolveDSSEVerificationSubject(ctx, "tenant", "attestation"); !errors.Is(err, context.Canceled) || v != (verificationapp.SubjectReference{}) {
		t.Fatal("cancellation returned ownership", err)
	}
}
