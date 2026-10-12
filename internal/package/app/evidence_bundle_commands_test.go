package app

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
)

func TestExportCommandsCommitSelectedSnapshotAndRollback(t *testing.T) {
	state := newPackageTestState()
	state.evidenceBundleSnapshot = EvidenceBundleSnapshot{SnapshotVersion: EvidenceBundleSnapshotVersion, TenantID: "ten_1", Evidence: []EvidenceBundleEvidence{{ID: "ev_2", Resources: application.ResourceReferences{ProductID: "private"}}, {ID: "ev_1", Resources: application.ResourceReferences{ProductID: "allowed"}}}, AuditChainHead: "sha256:head"}
	local := newPackageTestService(t, state)
	commands, err := NewExportCommands(ExportCommandConfig{Reader: serviceExportReader{local}, Transactions: serviceExportTransactions{state}, Authorizer: local.authorizer, Hasher: local.canonicalizer, Signer: local.signer, Clock: local.clock, IDs: local.ids})
	if err != nil {
		t.Fatal(err)
	}
	state.authorize = func(r application.AuthorizationRequest) error {
		if r.Resources.ProductID == "private" {
			return application.ErrForbidden
		}
		return nil
	}
	bundle, err := commands.ExportEvidenceBundle(t.Context(), packageTestActor(), "", nil)
	if err != nil || len(bundle.EvidenceIDs) != 1 || bundle.EvidenceIDs[0] != "ev_1" || len(state.evidenceBundles) != 1 || len(state.signatures) != 1 || len(state.audit) != 1 || len(state.outbox) != 0 || state.audit[0].SignatureRef != bundle.SignatureRefs[0] {
		t.Fatalf("bundle=%#v err=%v", bundle, err)
	}
	if _, err := commands.ExportEvidenceBundle(t.Context(), packageTestActor(), "", []string{"ev_2"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("explicit forbidden evidence exported", err)
	}
	state.auditErr = errPackageTestFailure
	if result, err := commands.ExportEvidenceBundle(t.Context(), packageTestActor(), "", []string{"ev_1"}); !errors.Is(err, errPackageTestFailure) || result.ID != "" || len(state.evidenceBundles) != 1 || len(state.signatures) != 1 {
		t.Fatal("partial writes after failed audit", err)
	}
	state.auditErr = nil
	state.authorize = func(r application.AuthorizationRequest) error {
		if !r.ScopeOnly {
			return errPackageTestFailure
		}
		return nil
	}
	if _, err := commands.ExportEvidenceBundle(t.Context(), packageTestActor(), "", nil); !errors.Is(err, errPackageTestFailure) {
		t.Fatal("backend failure was silently filtered", err)
	}
}
