package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

type memoryTransparencyPorts interface {
	e.PublicTransparencyMetadataReader
	e.PublicTransparencyVerificationReader
	ReadPublicTransparencyFetch(context.Context, string, string) (e.PublicTransparencyFetchSource, error)
	InsertFocusedPublicTransparencyLog(context.Context, d.PublicTransparencyLog) error
	InsertFocusedPublicTransparencyEntry(context.Context, d.PublicTransparencyLogEntry) error
	UpdateFocusedPublicTransparencyVerification(context.Context, d.PublicTransparencyLogEntry, d.PublicTransparencyLogEntry) error
}

func memoryTransparencyFixture(t *testing.T) (*memoryUnitOfWork, memoryTransparencyPorts) {
	t.Helper()
	_, tx := memoryQuestionnaireFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		tx.state.PublicTransparencyLogs[tenant+"-log"] = domain.PublicTransparencyLog{ID: tenant + "-log", TenantID: tenant, Name: strings.Repeat("private", 10000), PublicKey: strings.Repeat("unused", 10000), Endpoint: "https://log.example.test"}
		tx.state.MerkleBatches[tenant+"-batch"] = domain.MerkleBatch{ID: tenant + "-batch", TenantID: tenant, RootHash: "sha256:" + strings.Repeat("a", 64), LeafHashes: []string{strings.Repeat("unused", 10000)}, SignatureRefs: []string{strings.Repeat("unused", 10000)}}
		tx.state.TransparencyCheckpoints[tenant+"-checkpoint"] = domain.TransparencyCheckpoint{ID: tenant + "-checkpoint", TenantID: tenant, BatchID: tenant + "-batch", Provider: strings.Repeat("unused", 10000)}
		tx.state.PublicTransparencyEntries[tenant+"-entry"] = domain.PublicTransparencyLogEntry{ID: tenant + "-entry", TenantID: tenant, LogID: tenant + "-log", CheckpointID: tenant + "-checkpoint", MerkleBatchID: tenant + "-batch", ExternalID: "external", EntryHash: "sha256:" + strings.Repeat("b", 64), State: "published", SchemaVersion: domain.PublicTransparencyEntryVersion, CreatedAt: fixedNow(), VerificationChecks: []domain.VerifyCheck{{Detail: strings.Repeat("private", 10000)}}, VerificationLimitations: []string{strings.Repeat("private", 10000)}}
	}
	r, ok := tx.Repositories().Future.(memoryTransparencyPorts)
	if !ok {
		t.Fatal("memory future repository lacks focused transparency ports")
	}
	return tx, r
}

func TestMemoryTransparencyReadersReturnOnlyBoundedOwnedSourceCoordinates(t *testing.T) {
	tx, r := memoryTransparencyFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	src, err := r.ReadPublicTransparencyPublication(t.Context(), "tenant", "tenant-log", "tenant-checkpoint")
	want := e.PublicTransparencyPublicationSource{TenantID: "tenant", LogID: "tenant-log", CheckpointID: "tenant-checkpoint", BatchID: "tenant-batch", RootHash: "sha256:" + strings.Repeat("a", 64)}
	if err != nil || src != want {
		t.Fatal("publication transferred irrelevant metadata or lost root", src, err)
	}
	v, err := r.ReadPublicTransparencyVerification(t.Context(), "tenant", "tenant-entry")
	expected := d.PublicTransparencyLogEntry{ID: "tenant-entry", TenantID: "tenant", LogID: "tenant-log", CheckpointID: "tenant-checkpoint", MerkleBatchID: "tenant-batch", ExternalID: "external", EntryHash: "sha256:" + strings.Repeat("b", 64), State: "published", SchemaVersion: domain.PublicTransparencyEntryVersion, CreatedAt: fixedNow()}
	if err != nil || !reflect.DeepEqual(v, expected) {
		t.Fatal("verification read transferred private historical diagnostics", v, err)
	}
	fetch, err := r.ReadPublicTransparencyFetch(t.Context(), "tenant", "tenant-entry")
	if err != nil || !reflect.DeepEqual(fetch, e.PublicTransparencyFetchSource{Entry: expected, Endpoint: "https://log.example.test"}) {
		t.Fatal("fetch widened source projection", fetch, err)
	}
	for _, ids := range [][2]string{{"foreign-log", "tenant-checkpoint"}, {"tenant-log", "foreign-checkpoint"}} {
		if _, err := r.ReadPublicTransparencyPublication(t.Context(), "tenant", ids[0], ids[1]); !errors.Is(err, ErrNotFound) {
			t.Fatal("publication crossed tenant", err)
		}
	}
	if _, err := r.ReadPublicTransparencyFetch(t.Context(), "tenant", "foreign-entry"); !errors.Is(err, ErrNotFound) {
		t.Fatal("fetch crossed tenant", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("transparency reads changed storage")
	}
	p := tx.state.PublicTransparencyEntries["tenant-entry"]
	p.ExternalID = strings.Repeat("x", 1025)
	tx.state.PublicTransparencyEntries[p.ID] = p
	if got, err := r.ReadPublicTransparencyVerification(t.Context(), "tenant", p.ID); !errors.Is(err, ErrValidation) || !reflect.DeepEqual(got, d.PublicTransparencyLogEntry{}) {
		t.Fatal("oversized selected entry escaped", got, err)
	}
	p.ExternalID = "external"
	tx.state.PublicTransparencyEntries[p.ID] = p
	cp := tx.state.TransparencyCheckpoints[p.CheckpointID]
	cp.BatchID = "foreign-batch"
	tx.state.TransparencyCheckpoints[cp.ID] = cp
	if _, err := r.ReadPublicTransparencyVerification(t.Context(), "tenant", p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("verification accepted incoherent root chain", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := r.ReadPublicTransparencyTenant(ctx, "tenant"); !errors.Is(err, context.Canceled) {
		t.Fatal("tenant read ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadPublicTransparencyPublication(t.Context(), "tenant", "tenant-log", "tenant-checkpoint"); !errors.Is(err, ErrConflict) {
		t.Fatal("read used closed transaction", err)
	}
}

func TestMemoryTransparencyWritesBindCommitmentAndCompareFullAssessment(t *testing.T) {
	tx, r := memoryTransparencyFixture(t)
	log, err := e.BuildPublicTransparencyLog("new-log", "tenant", e.PublicTransparencyLogInput{Name: "New", Endpoint: "https://log.example.test", PublicKey: "public-only"}, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.InsertFocusedPublicTransparencyLog(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	if tx.state.PublicTransparencyLogs[log.ID] != (domain.PublicTransparencyLog{ID: log.ID, TenantID: log.TenantID, Name: log.Name, Endpoint: log.Endpoint, PublicKey: log.PublicKey, State: log.State, SchemaVersion: log.SchemaVersion, CreatedAt: log.CreatedAt}) {
		t.Fatal("log mapper dropped fields")
	}
	input := e.PublicTransparencyPublicationInput{LogID: log.ID, CheckpointID: "tenant-checkpoint", ExternalID: "new-external"}
	src, err := r.ReadPublicTransparencyPublication(t.Context(), "tenant", input.LogID, input.CheckpointID)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := e.BuildPublicTransparencyPublication("new-entry", "tenant", input, src, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.InsertFocusedPublicTransparencyEntry(t.Context(), pub); err != nil {
		t.Fatal(err)
	}
	expected := domain.PublicTransparencyLogEntry{ID: pub.ID, TenantID: pub.TenantID, LogID: pub.LogID, CheckpointID: pub.CheckpointID, MerkleBatchID: pub.MerkleBatchID, ExternalID: pub.ExternalID, EntryHash: pub.EntryHash, State: pub.State, SchemaVersion: pub.SchemaVersion, CreatedAt: pub.CreatedAt}
	if !reflect.DeepEqual(tx.state.PublicTransparencyEntries[pub.ID], expected) {
		t.Fatal("publication mapper added authority or dropped fields")
	}
	first, err := e.BuildPublicTransparencyVerification(pub, e.PublicTransparencyProofInput{RootHash: pub.EntryHash, TreeSize: 1}, "", fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateFocusedPublicTransparencyVerification(t.Context(), first, pub); err != nil {
		t.Fatal(err)
	}
	expected.State, expected.InclusionRootHash, expected.InclusionProofHash, expected.InclusionVerifiedAt = first.State, first.InclusionRootHash, first.InclusionProofHash, first.InclusionVerifiedAt
	expected.VerificationLimitations = append([]string(nil), first.VerificationLimitations...)
	for _, c := range first.VerificationChecks {
		expected.VerificationChecks = append(expected.VerificationChecks, domain.VerifyCheck{Name: c.Name, Result: c.Result, Detail: c.Detail})
	}
	if !reflect.DeepEqual(tx.state.PublicTransparencyEntries[pub.ID], expected) {
		t.Fatal("assessment mapper dropped fields")
	}
	stale := e.ClonePublicTransparencyEntry(first)
	second, err := e.BuildPublicTransparencyVerification(first, e.PublicTransparencyProofInput{RootHash: pub.EntryHash, TreeSize: 1}, "fetched", fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if second.State != first.State || second.InclusionProofHash == first.InclusionProofHash {
		t.Fatal("test does not distinguish same-state assessments")
	}
	if err := r.UpdateFocusedPublicTransparencyVerification(t.Context(), second, first); err != nil {
		t.Fatal(err)
	}
	second.VerificationChecks[0].Detail, second.VerificationLimitations[0] = "mutated", "mutated"
	*second.InclusionVerifiedAt = second.InclusionVerifiedAt.AddDate(1, 0, 0)
	saved := tx.state.PublicTransparencyEntries[pub.ID]
	if saved.VerificationChecks[0].Detail == "mutated" || saved.VerificationLimitations[0] == "mutated" || saved.InclusionVerifiedAt.Equal(*second.InclusionVerifiedAt) {
		t.Fatal("assessment retained caller pointers or arrays")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateFocusedPublicTransparencyVerification(t.Context(), first, stale); !errors.Is(err, ErrConflict) {
		t.Fatal("same-state stale assessment bypassed compare-and-swap", err)
	}
	pub.ID, pub.EntryHash = "forged-hash", "sha256:"+strings.Repeat("c", 64)
	if err := r.InsertFocusedPublicTransparencyEntry(t.Context(), pub); !errors.Is(err, ErrValidation) {
		t.Fatal("forged publication commitment accepted", err)
	}
	pub.ID, pub.LogID = "foreign-log-entry", "foreign-log"
	if err := r.InsertFocusedPublicTransparencyEntry(t.Context(), pub); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign log publication accepted", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("rejected stale or forged write changed immutable records")
	}
}
