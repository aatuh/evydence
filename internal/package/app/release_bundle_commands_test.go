package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
)

func TestReleaseBundleCommandsCommitSignedSnapshotAtomically(t *testing.T) {
	state := newPackageTestState()
	state.releaseBundleSnapshot = ReleaseBundleSnapshot{SnapshotVersion: ReleaseBundleSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", ReleaseVersion: "1", ReleaseState: "draft", EvidenceIDs: []string{"ev_2", "ev_1"}, ChainSequence: 3, ChainHeadHash: "sha256:head"}
	local := newPackageTestService(t, state)
	commands, err := NewReleaseBundleCommands(ReleaseBundleCommandConfig{Reader: serviceReleaseBundleReader{local}, Transactions: serviceReleaseBundleTransactions{state}, Authorizer: local.authorizer, Hasher: local.canonicalizer, Signer: local.signer, Clock: local.clock, IDs: local.ids})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := commands.CreateReleaseBundle(t.Context(), packageTestActor(), "rel_1")
	if err != nil || len(state.releaseBundles) != 1 || len(state.signatures) != 1 || len(state.audit) != 1 || len(state.outbox) != 1 || state.audit[0].SignatureRef != bundle.SignatureRefs[0] || state.lastSigningRequest.PayloadHash != bundle.ManifestHash {
		t.Fatalf("bundle=%#v err=%v", bundle, err)
	}
	state.auditErr = errPackageTestFailure
	if result, err := commands.CreateReleaseBundle(t.Context(), packageTestActor(), "rel_1"); !errors.Is(err, errPackageTestFailure) || result.ID != "" || len(state.releaseBundles) != 1 || len(state.signatures) != 1 || len(state.outbox) != 1 {
		t.Fatal("audit failure did not roll back", err)
	}
	state.auditErr = nil
	state.authorize = func(r application.AuthorizationRequest) error {
		if !r.ScopeOnly {
			return application.ErrForbidden
		}
		return nil
	}
	if _, err := commands.CreateReleaseBundle(t.Context(), packageTestActor(), "rel_1"); !errors.Is(err, application.ErrForbidden) || len(state.releaseBundles) != 1 {
		t.Fatal("invalid grant wrote bundle", err)
	}
}
