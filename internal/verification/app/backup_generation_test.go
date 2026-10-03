package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type backupGenerationFake struct {
	auditVerificationFake
	commitment                    BackupStateCommitment
	manifests                     []verificationdomain.BackupManifest
	inside                        bool
	transactions, commitmentReads int
}

func (f *backupGenerationFake) ExecuteBackupGeneration(ctx context.Context, fn func(context.Context, BackupGenerationTransaction) error) error {
	f.transactions++
	copy := *f
	copy.inside = true
	copy.manifests, copy.audits = nil, nil
	copy.pageReads = 0
	err := fn(ctx, &copy)
	f.commitmentReads, f.payloadReads, f.pageReads = copy.commitmentReads, copy.payloadReads, copy.pageReads
	if err != nil {
		return err
	}
	if f.fail == "commit" {
		return errVerificationTestFailure
	}
	f.manifests, f.audits = copy.manifests, copy.audits
	return nil
}
func (f *backupGenerationFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopeAdmin || !r.TenantWide || r.ScopeOnly || !emptyResources(r.Resources) || f.fail == "scope" || f.fail == "auth" && f.inside {
		return ErrForbidden
	}
	return nil
}
func (f *backupGenerationFake) ReadBackupStateCommitment(context.Context, string) (BackupStateCommitment, error) {
	f.commitmentReads++
	if f.fail == "commitment" {
		return BackupStateCommitment{}, errVerificationTestFailure
	}
	return f.commitment, nil
}
func (f *backupGenerationFake) InsertBackupManifest(_ context.Context, m verificationdomain.BackupManifest) error {
	if f.fail == "insert" {
		return errVerificationTestFailure
	}
	f.manifests = append(f.manifests, cloneBackupManifest(m))
	return nil
}
func backupGenerationFixture(t *testing.T) (*BackupGenerationCommands, *backupGenerationFake) {
	t.Helper()
	base, af := auditVerificationFixture(t)
	f := &backupGenerationFake{auditVerificationFake: *af, commitment: BackupStateCommitment{TenantID: "tenant", Profile: BackupStateCommitmentProfile, StateHash: "sha256:" + strings.Repeat("a", 64), RowsRead: 2, BytesRead: 200, ResourceCounts: map[string]int{"audit_chain_entries": 1, "artifact_signatures": 0, "cosign_verifications": 0, "evidence": 0, "merkle_batches": 0, "object_retention_policies": 0, "release_bundles": 0, "transparency_checkpoints": 0}}}
	c, err := NewBackupGenerationCommands(BackupGenerationConfig{Transactions: f, Authorizer: f, Hasher: base.config.Hasher, Verifier: base.config.Verifier, Clock: base.config.Clock, IDs: base.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func TestBackupGenerationCreatesFreshBoundedTenantManifestAtomically(t *testing.T) {
	c, f := backupGenerationFixture(t)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	r, err := c.GenerateBackupManifest(t.Context(), a)
	if err != nil || r.ID != "bak_receipt" || r.TenantID != "tenant" || r.StateHash != f.commitment.StateHash || !reflect.DeepEqual(r.ResourceCounts, f.commitment.ResourceCounts) || len(r.ConsistencyChecks) != 8 || r.ConsistencyChecks[7].Result != "passed" || r.SchemaVersion != verificationdomain.BackupManifestTenantSchemaVersion || len(f.manifests) != 1 || len(f.audits) != 1 || len(f.results)+len(f.jobs) != 0 {
		t.Fatal(r, err)
	}
	if f.audits[0].EntryType != "backup_manifest.generated" || f.audits[0].SubjectType != "backup_manifest" || f.audits[0].PayloadHash != r.StateHash || f.audits[0].SubjectID != r.ID {
		t.Fatal(f.audits)
	}
	r.ResourceCounts["evidence"] = 99
	r.ConsistencyChecks[0].Result = "failed"
	r.Limitations[0] = "changed"
	if f.manifests[0].ResourceCounts["evidence"] != 0 || f.manifests[0].ConsistencyChecks[0].Result != "passed" || f.manifests[0].Limitations[0] == "changed" {
		t.Fatal("published manifest aliases")
	}
	for _, failure := range []string{"scope", "auth", "commitment", "read", "insert", "audit", "commit"} {
		c, f := backupGenerationFixture(t)
		f.fail = failure
		r, err := c.GenerateBackupManifest(t.Context(), a)
		want := errVerificationTestFailure
		if failure == "scope" || failure == "auth" {
			want = ErrForbidden
		}
		if !errors.Is(err, want) || r.ID != "" || len(f.manifests)+len(f.audits)+len(f.jobs)+len(f.results) != 0 {
			t.Fatal(failure, r, err)
		}
		if (failure == "scope" || failure == "auth") && f.commitmentReads+f.payloadReads+f.pageReads != 0 {
			t.Fatal("unauthorized backup reads")
		}
	}
	// Generation records an actual failed consistency observation; it must not
	// overwrite it with a fabricated passed receipt or refuse to record it.
	c, f = backupGenerationFixture(t)
	f.pages[0].Entries[0].Metadata["changed"] = true
	r, err = c.GenerateBackupManifest(t.Context(), a)
	if err != nil || r.ConsistencyChecks[4].Result != "failed" || r.ConsistencyChecks[7].Result != "failed" {
		t.Fatal("corruption hidden", r, err)
	}
}
func TestBackupGenerationRejectsForeignIncompleteMalformedAndOversizedCommitments(t *testing.T) {
	for name, mutate := range map[string]func(*backupGenerationFake){
		"foreign":        func(f *backupGenerationFake) { f.commitment.TenantID = "other" },
		"profile":        func(f *backupGenerationFake) { f.commitment.Profile = "legacy-global" },
		"hash":           func(f *backupGenerationFake) { f.commitment.StateHash = "sha256:short" },
		"hash uppercase": func(f *backupGenerationFake) { f.commitment.StateHash = "sha256:" + strings.Repeat("A", 64) },
		"zero rows":      func(f *backupGenerationFake) { f.commitment.RowsRead = 0 },
		"zero bytes":     func(f *backupGenerationFake) { f.commitment.BytesRead = 0 },
		"oversize rows":  func(f *backupGenerationFake) { f.commitment.RowsRead = MaxBackupStateCommitmentRows + 1 },
		"oversize bytes": func(f *backupGenerationFake) { f.commitment.BytesRead = MaxBackupStateCommitmentBytes + 1 },
		"missing count":  func(f *backupGenerationFake) { delete(f.commitment.ResourceCounts, "evidence") },
		"negative count": func(f *backupGenerationFake) { f.commitment.ResourceCounts["evidence"] = -1 },
		"overcount":      func(f *backupGenerationFake) { f.commitment.ResourceCounts["evidence"] = 100 },
		"unknown count":  func(f *backupGenerationFake) { f.commitment.ResourceCounts["invented"] = 0 },
		"audit count":    func(f *backupGenerationFake) { f.commitment.ResourceCounts["audit_chain_entries"] = 0 },
	} {
		c, f := backupGenerationFixture(t)
		mutate(f)
		r, err := c.GenerateBackupManifest(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"})
		want := ErrConflict
		if name == "foreign" {
			want = ErrNotFound
		}
		if !errors.Is(err, want) || r.ID != "" || len(f.manifests)+len(f.audits) != 0 {
			t.Fatal(name, r, err)
		}
	}
	c, f := backupGenerationFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if _, err := c.GenerateBackupManifest(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}); !errors.Is(err, context.Canceled) || f.transactions != 0 {
			t.Fatal(err)
		}
	}
	for _, a := range []identitydomain.Actor{{}, {TenantID: "tenant"}, {KeyID: "caller"}} {
		if _, err := c.GenerateBackupManifest(t.Context(), a); !errors.Is(err, ErrForbidden) || f.transactions != 0 {
			t.Fatal(err)
		}
	}
	for _, mutate := range []func(*BackupGenerationConfig){func(c *BackupGenerationConfig) { c.Transactions = nil }, func(c *BackupGenerationConfig) { c.Authorizer = nil }, func(c *BackupGenerationConfig) { c.Hasher = nil }, func(c *BackupGenerationConfig) { c.Verifier = nil }, func(c *BackupGenerationConfig) { c.Clock = nil }, func(c *BackupGenerationConfig) { c.IDs = nil }} {
		config := c.config
		mutate(&config)
		if s, err := NewBackupGenerationCommands(config); !errors.Is(err, ErrValidation) || s != nil {
			t.Fatal(s, err)
		}
	}
}
