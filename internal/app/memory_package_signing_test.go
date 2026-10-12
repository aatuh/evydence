package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

type memoryPackageSignatureValidator interface {
	ValidatePackageSignature(context.Context, domain.Signature, string) error
}

func memoryPackageSigningFixture(t *testing.T) (*memoryUnitOfWork, packageapp.PackageSigner, memoryPackageSignatureValidator) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("a", ed25519.SeedSize)))
	tx.state.SigningKeys["key"] = domain.SigningKey{ID: "key", TenantID: "tenant", KID: "key", Version: 2, Provider: "local_ed25519", Algorithm: "Ed25519", Status: "active", PublicKey: base64.RawStdEncoding.EncodeToString(private[ed25519.SeedSize:]), Private: private, ValidFrom: fixedNow().Add(-time.Hour), CreatedAt: fixedNow().Add(-time.Hour)}
	signer, ok := tx.Repositories().Signatures.(packageapp.PackageSigner)
	if !ok {
		t.Fatal("memory signing repository lacks focused local package signer")
	}
	validator, ok := tx.Repositories().Signatures.(memoryPackageSignatureValidator)
	if !ok {
		t.Fatal("memory signing repository lacks focused signature revalidation")
	}
	return tx, signer, validator
}

func memoryPackageSigningRequest() packageapp.PackageSigningRequest {
	return packageapp.PackageSigningRequest{TenantID: "tenant", SubjectType: "release_bundle", SubjectID: "bundle", PayloadHash: "sha256:" + strings.Repeat("b", 64), CreatedAt: fixedNow()}
}

func TestMemoryPackageSigningUsesCurrentTenantKeyAndValidatesExactHash(t *testing.T) {
	tx, signer, validator := memoryPackageSigningFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	r := memoryPackageSigningRequest()
	sig, err := signer.SignPackage(t.Context(), r)
	if err != nil || sig.ID == "" || sig.TenantID != r.TenantID || sig.KeyID != "key" || sig.SubjectType != r.SubjectType || sig.SubjectID != r.SubjectID || sig.Algorithm != "Ed25519" || !sig.CreatedAt.Equal(r.CreatedAt) {
		t.Fatal("focused signature lost public binding", sig, err)
	}
	value, err := base64.RawStdEncoding.Strict().DecodeString(sig.Value)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(before.SigningKeys["key"].Private[ed25519.SeedSize:]), []byte(r.PayloadHash), value) {
		t.Fatal("signature does not verify exact requested hash", err)
	}
	stored := domain.Signature{ID: sig.ID, TenantID: sig.TenantID, KeyID: sig.KeyID, SubjectType: sig.SubjectType, SubjectID: sig.SubjectID, Algorithm: sig.Algorithm, Value: sig.Value, CreatedAt: sig.CreatedAt}
	if err := validator.ValidatePackageSignature(t.Context(), stored, r.PayloadHash); err != nil {
		t.Fatal(err)
	}
	if err := validator.ValidatePackageSignature(t.Context(), stored, "different-hash"); !errors.Is(err, ErrConflict) {
		t.Fatal("changed hash validated", err)
	}
	foreign := stored
	foreign.TenantID = "foreign"
	if err := validator.ValidatePackageSignature(t.Context(), foreign, r.PayloadHash); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign tenant signature validated", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("signing/revalidation mutated stored key or signature data")
	}
	key := tx.state.SigningKeys["key"]
	key.Status = "revoked"
	revoked := fixedNow()
	key.RevokedAt = &revoked
	tx.state.SigningKeys[key.ID] = key
	if err := validator.ValidatePackageSignature(t.Context(), stored, r.PayloadHash); !errors.Is(err, ErrConflict) {
		t.Fatal("revoked key remained valid before insertion", err)
	}
	if v, err := signer.SignPackage(t.Context(), r); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packageapp.PackageSignature{}) {
		t.Fatal("revoked key signed", err)
	}
}

func TestMemoryPackageSigningRejectsInvalidSelectedKeyAndCancellationWithoutData(t *testing.T) {
	for _, mutate := range []func(*domain.SigningKey){
		func(k *domain.SigningKey) { k.ID = "wrong-key" },
		func(k *domain.SigningKey) { k.Provider = "external_gateway" },
		func(k *domain.SigningKey) { k.Algorithm = "unknown" },
		func(k *domain.SigningKey) { k.Private = []byte("short") },
		func(k *domain.SigningKey) {
			k.PublicKey = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
		},
		func(k *domain.SigningKey) { k.ValidFrom = fixedNow().Add(time.Second) },
		func(k *domain.SigningKey) { at := fixedNow(); k.ValidUntil = &at },
		func(k *domain.SigningKey) { at := fixedNow(); k.CompromisedAt = &at },
	} {
		tx, signer, _ := memoryPackageSigningFixture(t)
		key := tx.state.SigningKeys["key"]
		mutate(&key)
		tx.state.SigningKeys["key"] = key
		if v, err := signer.SignPackage(t.Context(), memoryPackageSigningRequest()); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packageapp.PackageSignature{}) {
			t.Fatal("invalid selected key returned signature", err)
		}
	}
	tx, signer, _ := memoryPackageSigningFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := signer.SignPackage(ctx, memoryPackageSigningRequest()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, packageapp.PackageSignature{}) {
		t.Fatal("cancelled signer returned data", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v, err := signer.SignPackage(t.Context(), memoryPackageSigningRequest()); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packageapp.PackageSignature{}) {
		t.Fatal("closed signer returned data", err)
	}
}

func TestMemoryPackageSigningSelectsHighestVersionAndStableIDWithoutExpiredFallback(t *testing.T) {
	tx, signer, _ := memoryPackageSigningFixture(t)
	key := tx.state.SigningKeys["key"]
	key.ID = "a-key"
	tx.state.SigningKeys[key.ID] = key
	foreign := key
	foreign.ID = "foreign-key"
	foreign.TenantID = "foreign"
	foreign.Version = 99
	tx.state.SigningKeys[foreign.ID] = foreign
	request := memoryPackageSigningRequest()
	v, err := signer.SignPackage(t.Context(), request)
	if err != nil || v.KeyID != "a-key" {
		t.Fatal("same-version selection or tenant filtering changed", v, err)
	}
	latest := key
	latest.ID = "latest"
	latest.Version = 3
	tx.state.SigningKeys[latest.ID] = latest
	v, err = signer.SignPackage(t.Context(), request)
	if err != nil || v.KeyID != "latest" {
		t.Fatal("highest-version current key not selected", v, err)
	}
	expiry := request.CreatedAt
	latest.ValidUntil = &expiry
	tx.state.SigningKeys[latest.ID] = latest
	if v, err := signer.SignPackage(t.Context(), request); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, packageapp.PackageSignature{}) {
		t.Fatal("expired latest key silently fell back to older key", err)
	}
}
