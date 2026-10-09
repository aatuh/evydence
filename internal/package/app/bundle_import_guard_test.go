package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type importGuardFixture struct {
	ImportTransaction // Reads, hashing, and writes are not replay capabilities.
	locks             int
	deny              bool
}

func (f *importGuardFixture) ExecuteBundleImport(ctx context.Context, fn func(context.Context, ImportTransaction) error) error {
	return fn(ctx, f)
}
func (f *importGuardFixture) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != "bundle:write" || !r.TenantWide || r.ScopeOnly || f.deny {
		return application.ErrForbidden
	}
	return nil
}
func (f *importGuardFixture) LockBundleImportTenant(_ context.Context, tenant string) error {
	if tenant != "ten_1" {
		return ErrNotFound
	}
	f.locks++
	return nil
}

type importGuardUnusedHasher struct{ ManifestHasher }

func portableImportGuardInput() packagedomain.EvidenceBundle {
	return packagedomain.EvidenceBundle{ID: "untrusted-source-bundle", TenantID: "foreign-source-label", ReleaseID: "missing-source-release", EvidenceIDs: []string{" source-id ", "source-id"}, SignatureRefs: []string{"untrusted-signature"}, ManifestHash: "historical-hash-label", Manifest: map[string]any{"bundle_version": packagedomain.EvidenceBundleSchemaVersion, "evidence_ids": []string{" source-id "}, "private-input": "not persisted"}}
}

func TestBundleImportGuardChecksOnlyTargetTenantAndCurrentAuthority(t *testing.T) {
	f := &importGuardFixture{}
	s, err := NewImportCommands(ImportCommandConfig{Transactions: f, Authorizer: f, Hasher: importGuardUnusedHasher{}, Clock: application.ClockFunc(func() time.Time { panic("guard allocated time") }), IDs: application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })})
	if err != nil {
		t.Fatal(err)
	}
	b := portableImportGuardInput()
	if err := s.AuthorizeBundleImport(t.Context(), packageTestActor(), b); err != nil || f.locks != 1 {
		t.Fatal("guard resolved source IDs, hashed input or failed to lock target", err, f.locks)
	}
	f.deny = true
	if err := s.AuthorizeBundleImport(t.Context(), packageTestActor(), b); !errors.Is(err, application.ErrForbidden) || f.locks != 1 {
		t.Fatal("revoked permission reached target lock", err, f.locks)
	}
	f.deny = false
	a := packageTestActor()
	a.TenantID = "missing"
	if err := s.AuthorizeBundleImport(t.Context(), a, b); !errors.Is(err, ErrNotFound) {
		t.Fatal("guard accepted missing target", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.AuthorizeBundleImport(ctx, packageTestActor(), b); !errors.Is(err, context.Canceled) || f.locks != 1 {
		t.Fatal("cancelled guard did work", err, f.locks)
	}
}

func TestPortableBundleInputBoundsRawReferencesBeforeNormalization(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  func(*packagedomain.EvidenceBundle)
	}{
		{"source identity", func(b *packagedomain.EvidenceBundle) { b.TenantID = strings.Repeat(" ", 1025) }},
		{"source NUL", func(b *packagedomain.EvidenceBundle) { b.ReleaseID = "source\x00" }},
		{"invalid UTF-8", func(b *packagedomain.EvidenceBundle) { b.ID = string([]byte{0xff}) }},
		{"hash budget", func(b *packagedomain.EvidenceBundle) { b.ManifestHash = strings.Repeat("h", 129) }},
		{"hash blank", func(b *packagedomain.EvidenceBundle) { b.ManifestHash = " " }},
		{"outer ID count", func(b *packagedomain.EvidenceBundle) { b.EvidenceIDs = make([]string, 1025) }},
		{"signature count", func(b *packagedomain.EvidenceBundle) { b.SignatureRefs = make([]string, 1025) }},
		{"raw outer ID", func(b *packagedomain.EvidenceBundle) { b.EvidenceIDs = []string{strings.Repeat(" ", 1024) + "x"} }},
		{"raw manifest ID", func(b *packagedomain.EvidenceBundle) {
			b.Manifest["evidence_ids"] = []string{strings.Repeat(" ", 1024) + "x"}
		}},
		{"manifest ID count", func(b *packagedomain.EvidenceBundle) { b.Manifest["evidence_ids"] = make([]string, 1025) }},
		{"manifest duplicate", func(b *packagedomain.EvidenceBundle) { b.Manifest["evidence_ids"] = []string{"x", " x "} }},
		{"manifest null item", func(b *packagedomain.EvidenceBundle) { b.Manifest["evidence_ids"] = []any{nil} }},
		{"manifest ID NUL", func(b *packagedomain.EvidenceBundle) { b.Manifest["evidence_ids"] = []string{"id\x00"} }},
		{"manifest encoded budget", func(b *packagedomain.EvidenceBundle) {
			for _, key := range []string{"a", "b", "c", "d", "e"} {
				b.Manifest[key] = strings.Repeat("x", 16000)
			}
		}},
		{"manifest depth", func(b *packagedomain.EvidenceBundle) {
			var value any = "x"
			for range 33 {
				value = map[string]any{"nested": value}
			}
			b.Manifest["extra"] = value
		}},
		{"unencodable manifest", func(b *packagedomain.EvidenceBundle) { b.Manifest["extra"] = func() {} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := portableImportGuardInput()
			tc.bad(&b)
			if err := ValidatePortableBundleInput(b); !errors.Is(err, ErrValidation) {
				t.Fatal("invalid portable input accepted", err)
			}
		})
	}
	b := portableImportGuardInput()
	b.EvidenceIDs = nil
	b.Manifest["evidence_ids"] = []string{}
	if err := ValidatePortableBundleInput(b); err != nil {
		t.Fatal("empty selection no longer allowed", err)
	}
}
