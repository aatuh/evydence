package app

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func publicProofLocalFixture(t *testing.T) (*Ledger, domain.Actor, domain.PublicTransparencyLogEntry) {
	t.Helper()
	l := newLegacyLedgerFixture(Config{APIKeyPepper: "test", Now: fixedNow})
	_, _, secret, err := l.BootstrapTenant(t.Context(), "Tenant", "operator", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := l.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	v := domain.PublicTransparencyLogEntry{ID: "entry", TenantID: a.TenantID, LogID: "log", CheckpointID: "cp", MerkleBatchID: "batch", ExternalID: "external", EntryHash: sampleDigest("entry"), State: "published", SchemaVersion: domain.PublicTransparencyEntryVersion, CreatedAt: fixedNow()}
	l.publicLogs["log"] = domain.PublicTransparencyLog{ID: "log", TenantID: a.TenantID}
	l.transparency["cp"] = domain.TransparencyCheckpoint{ID: "cp", TenantID: a.TenantID, BatchID: "batch"}
	l.merkleBatches["batch"] = domain.MerkleBatch{ID: "batch", TenantID: a.TenantID}
	l.publicLogEntries[v.ID] = v
	return l, a, v
}

func TestPublicTransparencyVerificationRequiresOwnedRootChain(t *testing.T) {
	for _, mode := range []string{"log", "checkpoint", "batch", "batch-link", "tenant", "human-product"} {
		t.Run(mode, func(t *testing.T) {
			l, a, v := publicProofLocalFixture(t)
			want := ErrNotFound
			switch mode {
			case "log":
				x := l.publicLogs["log"]
				x.TenantID = "other"
				l.publicLogs["log"] = x
			case "checkpoint":
				x := l.transparency["cp"]
				x.TenantID = "other"
				l.transparency["cp"] = x
			case "batch":
				x := l.merkleBatches["batch"]
				x.TenantID = "other"
				l.merkleBatches["batch"] = x
			case "batch-link":
				x := l.transparency["cp"]
				x.BatchID = "different"
				l.transparency["cp"] = x
			case "tenant":
				delete(l.tenants, a.TenantID)
			case "human-product":
				a.KeyID, a.UserID = "", "user"
				a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"keys:admin"}}}
				want = ErrForbidden
			}
			before := len(l.chain[a.TenantID])
			out, err := l.VerifyPublicTransparencyLogEntry(t.Context(), a, v.ID, VerifyPublicTransparencyLogEntryInput{RootHash: v.EntryHash, TreeSize: 1})
			if !errors.Is(err, want) || out.ID != "" || !reflect.DeepEqual(l.publicLogEntries[v.ID], v) || len(l.chain[a.TenantID]) != before {
				t.Fatal("unowned proof persisted", mode, out, err)
			}
		})
	}
}

func TestPublicTransparencyVerificationDoesNotAliasCallerOrCommittedRecord(t *testing.T) {
	l, a, v := publicProofLocalFixture(t)
	proof := []string{" " + sampleDigest("sibling") + " "}
	original := append([]string(nil), proof...)
	out, err := l.VerifyPublicTransparencyLogEntry(t.Context(), a, v.ID, VerifyPublicTransparencyLogEntryInput{RootHash: sampleDigest("unrelated-root"), TreeSize: 2, InclusionProof: proof})
	if err != nil || out.State != "inclusion_not_verified" {
		t.Fatal(out, err)
	}
	if !reflect.DeepEqual(proof, original) {
		t.Fatal("verification changed caller proof material")
	}
	out.VerificationChecks[0].Result = "tampered"
	out.VerificationLimitations[0] = "tampered"
	*out.InclusionVerifiedAt = fixedNow().AddDate(1, 0, 0)
	stored := l.publicLogEntries[v.ID]
	if stored.VerificationChecks[0].Result == "tampered" || strings.Contains(stored.VerificationLimitations[0], "tampered") || !stored.InclusionVerifiedAt.Equal(fixedNow()) {
		t.Fatal("returned proof aliases committed assessment")
	}
}
