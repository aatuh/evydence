package app

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func memoryReleaseVerificationFixture(t *testing.T) (*memoryUnitOfWork, verificationapp.ReleaseBundleVerificationReader) {
	t.Helper()
	tx, signer, _ := memoryPackageSigningFixture(t)
	manifest := map[string]any{"exact": json.Number("9007199254740993"), "evidence_ids": []string{"evidence"}}
	hash, err := application.NormalizedJSONHash(manifest)
	if err != nil {
		t.Fatal(err)
	}
	request := memoryPackageSigningRequest()
	request.PayloadHash = hash
	sig, err := signer.SignPackage(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	tx.state.Signatures[sig.ID] = domain.Signature{ID: sig.ID, TenantID: sig.TenantID, SubjectType: sig.SubjectType, SubjectID: sig.SubjectID, KeyID: sig.KeyID, Algorithm: sig.Algorithm, Value: sig.Value, CreatedAt: sig.CreatedAt}
	tx.state.ReleaseBundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "tenant-release", State: "generated", Manifest: manifest, ManifestHash: hash, SignatureRefs: []string{sig.ID}, CreatedAt: fixedNow()}
	reader, ok := tx.Repositories().Verification.(verificationapp.ReleaseBundleVerificationReader)
	if !ok {
		t.Fatal("memory verification lacks current release-bundle reader")
	}
	return tx, reader
}

func TestMemoryReleaseBundleVerificationReadsDetachedPublicMaterialAndCurrentParents(t *testing.T) {
	tx, reader := memoryReleaseVerificationFixture(t)
	// Public verification must not depend on, copy or expose private material.
	key := tx.state.SigningKeys["key"]
	key.Private = []byte("private-material-marker")
	tx.state.SigningKeys["key"] = key
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := reader.ResolveReleaseBundleVerificationSubject(t.Context(), "tenant", "bundle")
	if err != nil || subject.Resources.ProductID != "tenant-product" || subject.Resources.ReleaseID != "tenant-release" {
		t.Fatal("verification scope lost current parents", subject, err)
	}
	v, err := reader.ReadReleaseBundleVerification(t.Context(), subject)
	if err != nil || v.Subject != subject || len(v.Signatures) != 1 || len(v.Keys) != 1 || v.Keys[0].ID != "key" || v.Keys[0].PublicKey != key.PublicKey {
		t.Fatal("public signature material missing", err)
	}
	if n, ok := v.Manifest["exact"].(json.Number); !ok || n.String() != "9007199254740993" {
		t.Fatal("verification rounded frozen number")
	}
	raw, err := json.Marshal(v)
	if err != nil || strings.Contains(string(raw), "private-material-marker") {
		t.Fatal("verification exposed private material", err)
	}
	v.Manifest["changed"] = "caller"
	v.SignatureRefs[0] = "changed"
	v.Keys[0].PublicKey = "changed"
	after, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("verification snapshot aliases stored material")
	}
	if value, err := reader.ResolveReleaseBundleVerificationSubject(t.Context(), "foreign", "bundle"); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(value, verificationapp.SubjectReference{}) {
		t.Fatal("foreign bundle returned scope", err)
	}
	release := tx.state.Releases["tenant-release"]
	release.ProductID = "foreign-product"
	tx.state.Releases[release.ID] = release
	if value, err := reader.ReadReleaseBundleVerification(t.Context(), subject); err == nil || !reflect.DeepEqual(value, verificationapp.ReleaseBundleVerificationSnapshot{}) {
		t.Fatal("reparented bundle retained old public snapshot", err)
	}
}

func TestMemoryReleaseBundleVerificationRejectsOversizedAndAmbiguousProjectionWithoutData(t *testing.T) {
	for _, mutate := range []func(*memoryUnitOfWork){
		func(tx *memoryUnitOfWork) {
			b := tx.state.ReleaseBundles["bundle"]
			b.SignatureRefs = append(b.SignatureRefs, b.SignatureRefs[0])
			tx.state.ReleaseBundles[b.ID] = b
		},
		func(tx *memoryUnitOfWork) {
			b := tx.state.ReleaseBundles["bundle"]
			b.Manifest = map[string]any{"large": strings.Repeat("x", verificationapp.MaxBundleVerificationBytes+1)}
			tx.state.ReleaseBundles[b.ID] = b
		},
		func(tx *memoryUnitOfWork) {
			for id, sig := range tx.state.Signatures {
				sig.Value = strings.Repeat("x", 16385)
				tx.state.Signatures[id] = sig
			}
		},
	} {
		tx, reader := memoryReleaseVerificationFixture(t)
		subject, err := reader.ResolveReleaseBundleVerificationSubject(t.Context(), "tenant", "bundle")
		if err != nil {
			t.Fatal(err)
		}
		mutate(tx)
		if value, err := reader.ReadReleaseBundleVerification(t.Context(), subject); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, verificationapp.ReleaseBundleVerificationSnapshot{}) {
			t.Fatal("invalid public projection returned data", err)
		}
	}
}
