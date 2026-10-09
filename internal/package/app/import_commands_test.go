package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestImportCommandsValidateManifestAndCommitReceiptWithAudit(t *testing.T) {
	state := newPackageTestState()
	local := newPackageTestService(t, state)
	commands, err := NewImportCommands(ImportCommandConfig{Transactions: serviceImportTransactions{state}, Authorizer: local.authorizer, Hasher: local.canonicalizer, Clock: local.clock, IDs: local.ids})
	if err != nil {
		t.Fatal(err)
	}
	bundle := packagedomain.EvidenceBundle{TenantID: "source_tenant", EvidenceIDs: []string{"ev_1"}, ManifestHash: "hash:manifest", Manifest: map[string]any{"bundle_version": packagedomain.EvidenceBundleSchemaVersion, "evidence_ids": []string{"ev_1"}, "private_input": "not persisted"}}
	record, err := commands.ImportEvidenceBundle(t.Context(), packageTestActor(), bundle)
	if err != nil || record.TenantID != "ten_1" || record.ImportedCount != 1 || record.Result != "accepted" || len(state.bundleImports) != 1 || len(state.audit) != 1 || state.audit[0].PayloadHash != record.BundleHash {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	state.auditErr = errPackageTestFailure
	if result, err := commands.ImportEvidenceBundle(t.Context(), packageTestActor(), bundle); !errors.Is(err, errPackageTestFailure) || result.ID != "" || len(state.bundleImports) != 1 || len(state.audit) != 1 {
		t.Fatalf("rollback=%#v err=%v", result, err)
	}
}

func TestImportCommandsRejectBeforeWritesAndReauthorize(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mutate       func(*packagedomain.EvidenceBundle, *packageTestState)
		want         error
		transactions int
	}{
		{"tampered hash", func(b *packagedomain.EvidenceBundle, _ *packageTestState) { b.ManifestHash = "wrong" }, ErrValidation, 0},
		{"wrong version", func(b *packagedomain.EvidenceBundle, _ *packageTestState) { b.Manifest["bundle_version"] = "future" }, ErrValidation, 0},
		{"duplicate manifest ids", func(b *packagedomain.EvidenceBundle, _ *packageTestState) {
			b.Manifest["evidence_ids"] = []string{"ev_1", "ev_1"}
		}, ErrValidation, 0},
		{"outer ids differ", func(b *packagedomain.EvidenceBundle, _ *packageTestState) { b.EvidenceIDs = []string{"ev_2"} }, ErrValidation, 0},
		{"revoked tenant permission", func(_ *packagedomain.EvidenceBundle, s *packageTestState) {
			s.authorize = func(r application.AuthorizationRequest) error {
				if r.TenantWide {
					return application.ErrForbidden
				}
				return nil
			}
		}, application.ErrForbidden, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newPackageTestState()
			local := newPackageTestService(t, state)
			bundle := packagedomain.EvidenceBundle{EvidenceIDs: []string{"ev_1"}, ManifestHash: "hash:manifest", Manifest: map[string]any{"bundle_version": packagedomain.EvidenceBundleSchemaVersion, "evidence_ids": []string{"ev_1"}}}
			tc.mutate(&bundle, state)
			commands, err := NewImportCommands(ImportCommandConfig{Transactions: serviceImportTransactions{state}, Authorizer: local.authorizer, Hasher: local.canonicalizer, Clock: local.clock, IDs: local.ids})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := commands.ImportEvidenceBundle(t.Context(), packageTestActor(), bundle); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if len(state.bundleImports) != 0 || len(state.audit) != 0 || state.executeCalls != tc.transactions {
				t.Fatal("invalid import wrote effects")
			}
		})
	}
}
