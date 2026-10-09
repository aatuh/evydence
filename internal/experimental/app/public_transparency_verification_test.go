package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type publicProofFixture struct {
	entry  d.PublicTransparencyLogEntry
	phase  string
	reads  int
	audits []application.AuditEvent
	cancel context.CancelFunc
}

func (f *publicProofFixture) ExecutePublicTransparencyVerification(ctx context.Context, _ string, fn func(context.Context, PublicTransparencyVerificationTransaction) error) error {
	before, n := f.entry, len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errTransparencyMetadataFixture
	}
	if err != nil {
		f.entry, f.audits = before, f.audits[:n]
	}
	return err
}
func (f *publicProofFixture) ReadPublicTransparencyVerification(context.Context, string, string) (d.PublicTransparencyLogEntry, error) {
	f.reads++
	if f.phase == "read" {
		return d.PublicTransparencyLogEntry{}, errTransparencyMetadataFixture
	}
	return f.entry, nil
}
func (f *publicProofFixture) UpdatePublicTransparencyVerification(_ context.Context, v, expected d.PublicTransparencyLogEntry) error {
	if f.phase == "update" {
		return errTransparencyMetadataFixture
	}
	if !SamePublicTransparencyAssessment(f.entry, expected) {
		return ErrConflict
	}
	f.entry = ClonePublicTransparencyEntry(v)
	return nil
}
func (f *publicProofFixture) AppendAudit(_ context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errTransparencyMetadataFixture
	}
	f.audits = append(f.audits, a)
	if f.cancel != nil {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func publicProofCommandFixture(t *testing.T) (*PublicTransparencyVerificationCommands, *publicProofFixture, identitydomain.Actor) {
	t.Helper()
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	f := &publicProofFixture{entry: d.PublicTransparencyLogEntry{ID: "entry", TenantID: "tenant", LogID: "log", CheckpointID: "checkpoint", MerkleBatchID: "batch", ExternalID: "external", EntryHash: "sha256:" + strings.Repeat("A", 64), State: "published", SchemaVersion: d.PublicTransparencyEntryVersion, CreatedAt: at}}
	c, err := NewPublicTransparencyVerificationCommands(PublicTransparencyVerificationConfig{Transactions: f, Clock: application.ClockFunc(func() time.Time { return at }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "-id" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
}
func TestPublicTransparencyVerificationPreservesCommitmentAndLocalResult(t *testing.T) {
	c, f, a := publicProofCommandFixture(t)
	in := PublicTransparencyProofInput{RootHash: " " + f.entry.EntryHash + " ", TreeSize: 1, InclusionProof: []string{}}
	if err := c.AuthorizeVerifyPublicTransparencyLogEntry(t.Context(), a, " entry ", in); err != nil || len(f.audits) != 0 {
		t.Fatal("guard writes", err)
	}
	out, err := c.VerifyPublicTransparencyLogEntry(t.Context(), a, " entry ", in)
	want, _ := application.NormalizedJSONHash(map[string]any{"entry_id": "entry", "leaf_hash": f.entry.EntryHash, "root_hash": f.entry.EntryHash, "leaf_index": 0, "tree_size": 1, "inclusion_proof": nil})
	if err != nil || out.State != "inclusion_verified" || out.InclusionProofHash != want || len(out.VerificationChecks) != 2 || len(out.VerificationLimitations) != 2 || len(f.audits) != 1 || f.audits[0].PayloadHash != want || f.audits[0].EntryType != "public_transparency_log_entry.inclusion_verified" {
		t.Fatal("proof/hash/audit contract changed", out, err)
	}
	out.VerificationChecks[0].Result = "tampered"
	*out.InclusionVerifiedAt = out.InclusionVerifiedAt.AddDate(1, 0, 0)
	if f.entry.VerificationChecks[0].Result == "tampered" || f.entry.InclusionVerifiedAt.Year() != 2026 {
		t.Fatal("returned assessment aliases storage")
	}
	in.LeafHash = "sha256:" + strings.Repeat("b", 64)
	in.RootHash = in.LeafHash
	failed, err := c.VerifyPublicTransparencyLogEntry(t.Context(), a, "entry", in)
	if err != nil || failed.State != "inclusion_not_verified" || failed.VerificationChecks[0].Result != "failed" || len(f.audits) != 2 || f.audits[1].EntryType != "public_transparency_log_entry.inclusion_not_verified" {
		t.Fatal("unbound leaf gained assurance", failed, err)
	}
	raw, err := EncodePublicTransparencyVerification(failed)
	var wire map[string]any
	if err != nil || json.Unmarshal(raw, &wire) != nil || wire["inclusion_proof_hash"] != failed.InclusionProofHash || strings.Contains(string(raw), "InclusionProofHash") {
		t.Fatal("wire contract changed", string(raw), err)
	}
}
func TestPublicTransparencyVerificationBoundsAuthorityAndAtomicFailures(t *testing.T) {
	for _, mode := range []string{"human-product", "foreign", "id", "root", "proof-count", "node", "leaf-index", "tree-size", "read", "update", "audit", "commit", "cancel", "stored-digest", "stored-id", "stored-state"} {
		t.Run(mode, func(t *testing.T) {
			c, f, a := publicProofCommandFixture(t)
			in := PublicTransparencyProofInput{RootHash: f.entry.EntryHash, TreeSize: 1}
			id := "entry"
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "human-product":
				a.KeyID, a.UserID = "", "user"
				a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: a.Scopes}}
			case "foreign":
				f.entry.TenantID = "other"
			case "id":
				id = strings.Repeat(" ", 1025) + id
			case "root":
				in.RootHash = strings.Repeat(" ", 129) + in.RootHash
			case "proof-count":
				in.InclusionProof = make([]string, 65)
			case "node":
				in.TreeSize = 2
				in.InclusionProof = []string{"sha256:invalid"}
			case "leaf-index":
				in.LeafIndex = 1
			case "tree-size":
				in.TreeSize = 0
			case "cancel":
				f.cancel = cancel
			case "stored-digest":
				f.entry.EntryHash = "sha256:bad"
			case "stored-id":
				f.entry.ExternalID = strings.Repeat("x", 1025)
			case "stored-state":
				f.entry.State = "unknown"
			default:
				f.phase = mode
			}
			before := f.entry
			out, err := c.VerifyPublicTransparencyLogEntry(ctx, a, id, in)
			if err == nil || !reflect.DeepEqual(out, d.PublicTransparencyLogEntry{}) || !reflect.DeepEqual(f.entry, before) || len(f.audits) != 0 {
				t.Fatal("failed assessment published", mode, out, err)
			}
			if mode == "human-product" && (!errors.Is(err, application.ErrForbidden) || f.reads != 0) {
				t.Fatal("product actor reached tenant read", err)
			}
		})
	}
}
func TestPublicTransparencyProofMathAndNormalization(t *testing.T) {
	body, err := os.ReadFile("../../../testdata/verification/rfc6962-tree-size-3.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		LeafHash       string   `json:"leaf_hash"`
		RootHash       string   `json:"root_hash"`
		LeafIndex      int      `json:"leaf_index"`
		TreeSize       int      `json:"tree_size"`
		InclusionProof []string `json:"inclusion_proof"`
	}
	if err := json.Unmarshal(body, &vector); err != nil {
		t.Fatal(err)
	}
	if !VerifyPublicTransparencyProof(vector.LeafHash, vector.RootHash, vector.LeafIndex, vector.TreeSize, vector.InclusionProof) || VerifyPublicTransparencyProof(vector.LeafHash, vector.RootHash, vector.LeafIndex, vector.TreeSize, nil) || VerifyPublicTransparencyProof(vector.LeafHash, vector.RootHash, vector.LeafIndex, vector.TreeSize, append(append([]string(nil), vector.InclusionProof...), vector.LeafHash)) {
		t.Fatal("irregular tree proof shape changed")
	}
	proof := []string{" " + vector.LeafHash + " "}
	copy := append([]string(nil), proof...)
	_, err = NormalizePublicTransparencyProofInput(" entry ", PublicTransparencyProofInput{RootHash: vector.RootHash, TreeSize: 2, InclusionProof: proof})
	if err != nil || !reflect.DeepEqual(proof, copy) {
		t.Fatal("normalization aliases caller", err)
	}
}

func TestPublicTransparencyVerificationRejectsInvalidGeneratedAuditAndClock(t *testing.T) {
	for _, mode := range []string{"audit-id", "clock", "cancel-before-read"} {
		t.Run(mode, func(t *testing.T) {
			c, f, a := publicProofCommandFixture(t)
			before := f.entry
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "audit-id":
				c.config.IDs = application.IDGeneratorFunc(func(string) string { return " invalid " })
			case "clock":
				c.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
			case "cancel-before-read":
				cancel()
			}
			out, err := c.VerifyPublicTransparencyLogEntry(ctx, a, "entry", PublicTransparencyProofInput{RootHash: f.entry.EntryHash, TreeSize: 1})
			if err == nil || out.ID != "" || !reflect.DeepEqual(f.entry, before) || len(f.audits) != 0 {
				t.Fatal("invalid generated assessment persisted", out, err)
			}
			if mode == "cancel-before-read" && (!errors.Is(err, context.Canceled) || f.reads != 0) {
				t.Fatal("cancellation reached source read", err)
			}
		})
	}
	if _, err := NewPublicTransparencyVerificationCommands(PublicTransparencyVerificationConfig{}); err == nil {
		t.Fatal("incomplete proof configuration accepted")
	}
}

func TestPublicTransparencyVerificationFetchedHashProfileAndSnapshotIdentity(t *testing.T) {
	_, f, _ := publicProofCommandFixture(t)
	in := PublicTransparencyProofInput{RootHash: f.entry.EntryHash, TreeSize: 2, InclusionProof: []string{f.entry.EntryHash}}
	v, err := BuildPublicTransparencyVerification(f.entry, in, "fetched", f.entry.CreatedAt)
	want, _ := application.NormalizedJSONHash(map[string]any{"entry_id": "entry", "leaf_hash": f.entry.EntryHash, "root_hash": f.entry.EntryHash, "leaf_index": 0, "tree_size": 2, "inclusion_proof": in.InclusionProof, "source": "fetched"})
	if err != nil || v.InclusionProofHash != want || len(v.VerificationChecks) != 3 || len(v.VerificationLimitations) != 3 || v.State != "inclusion_not_verified" {
		t.Fatal("fetched source/hash profile changed", v, err)
	}
	if out, err := BuildPublicTransparencyVerification(f.entry, in, "operator-asserted-provider", f.entry.CreatedAt); !errors.Is(err, ErrValidation) || out.ID != "" {
		t.Fatal("unknown source claimed provenance", out, err)
	}
	for _, field := range []string{"id", "tenant", "log", "checkpoint", "batch", "external", "entry-hash", "state", "proof-hash", "root", "verified-at", "created-at", "schema"} {
		other := ClonePublicTransparencyEntry(v)
		switch field {
		case "id":
			other.ID += "-changed"
		case "tenant":
			other.TenantID += "-changed"
		case "log":
			other.LogID += "-changed"
		case "checkpoint":
			other.CheckpointID += "-changed"
		case "batch":
			other.MerkleBatchID += "-changed"
		case "external":
			other.ExternalID += "-changed"
		case "entry-hash":
			other.EntryHash = "sha256:" + strings.Repeat("b", 64)
		case "state":
			other.State = "inclusion_verified"
		case "proof-hash":
			other.InclusionProofHash = "sha256:" + strings.Repeat("b", 64)
		case "root":
			other.InclusionRootHash = "sha256:" + strings.Repeat("b", 64)
		case "verified-at":
			other.InclusionVerifiedAt = nil
		case "created-at":
			other.CreatedAt = other.CreatedAt.Add(time.Second)
		case "schema":
			other.SchemaVersion = "different"
		}
		if SamePublicTransparencyAssessment(v, other) {
			t.Fatal("snapshot ignored changed coordinate", field)
		}
	}
}
