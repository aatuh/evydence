package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestStoreApplyParserReplayIsIdempotentAcrossStaleConcurrentSnapshots(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_parser_replay_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = admin.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{
		LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	tenantID := "ten_parser_replay"
	if err := store.ApplyCriticalMutation(ctx, app.CriticalMutation{Tenants: []domain.Tenant{{
		ID: tenantID, Name: "Parser replay", CreatedAt: now,
	}}}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	source := domain.EvidenceItem{
		ID: "ev_parser_source", TenantID: tenantID, Type: "vulnerability_scan", Subtype: "generic",
		Title: "Parser source", SourceSystem: "scanner", UploadedBy: "collector", ObservedAt: now,
		EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion,
		PayloadRef: "object://tenants/ten_parser_replay/payloads/source", PayloadHash: "sha256:" + strings.Repeat("a", 64),
		CanonicalHash: "sha256:" + strings.Repeat("b", 64), Canonicalization: domain.CanonicalizationProfileVersion,
		TrustLevel: "L2", VerificationStatus: "pending", CreatedAt: now,
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, app.ReleaseLedgerMutation{Evidence: []domain.EvidenceItem{source}}); err != nil {
		t.Fatalf("seed source evidence: %v", err)
	}
	focused, ok, err := store.LoadParserReplayState(ctx, tenantID, source.ID, app.ParserVersionScannerAdaptersJSON)
	if err != nil || !ok || len(focused.Evidence) != 1 || focused.Evidence[source.ID].ID != source.ID || len(focused.Chain[tenantID]) != 0 || len(focused.Scans) != 0 {
		t.Fatalf("focused parser replay source=%#v chain=%#v ok=%v error=%v", focused.Evidence, focused.Chain, ok, err)
	}
	foreign, ok, err := store.LoadParserReplayState(ctx, "ten_other", source.ID, app.ParserVersionScannerAdaptersJSON)
	if err != nil || !ok || len(foreign.Evidence) != 0 || len(foreign.Chain) != 0 {
		t.Fatalf("foreign parser replay source=%#v chain=%#v ok=%v error=%v", foreign.Evidence, foreign.Chain, ok, err)
	}

	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_parser","findings":[]}`)
	staleSource := source
	staleSource.ReleaseID = "rel_stale_snapshot"
	staleRequest := app.ParserReplayRequest{
		TenantID: tenantID, EvidenceID: source.ID, ParserVersion: app.ParserVersionScannerAdaptersJSON,
		ActorID: "operator", Now: now.Add(30 * time.Second),
	}
	staleState := app.PersistedState{
		Evidence: map[string]domain.EvidenceItem{source.ID: staleSource},
		Chain:    map[string][]domain.AuditChainEntry{},
	}
	staleResult, err := app.ReplayParserEvidence(&staleState, raw, staleRequest)
	if err != nil {
		t.Fatalf("prepare stale replay: %v", err)
	}
	staleMutation, err := app.ParserReplayMutation(&staleState, staleRequest, staleResult)
	if err != nil {
		t.Fatalf("prepare stale mutation: %v", err)
	}
	if id, created, err := store.ApplyParserReplay(ctx, staleRequest, staleMutation); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale source replay = id %q created %v error %v, want conflict", id, created, err)
	}

	requests := []app.ParserReplayRequest{
		{TenantID: tenantID, EvidenceID: source.ID, ParserVersion: app.ParserVersionScannerAdaptersJSON, ActorID: "operator", Now: now.Add(time.Minute)},
		{TenantID: tenantID, EvidenceID: source.ID, ParserVersion: app.ParserVersionScannerAdaptersJSON, ActorID: "operator", Now: now.Add(time.Minute + time.Second)},
	}
	mutations := make([]app.ReleaseLedgerMutation, len(requests))
	for index, request := range requests {
		state := app.PersistedState{
			Evidence: map[string]domain.EvidenceItem{source.ID: source},
			Chain:    map[string][]domain.AuditChainEntry{},
		}
		result, err := app.ReplayParserEvidence(&state, raw, request)
		if err != nil {
			t.Fatalf("prepare replay %d: %v", index, err)
		}
		mutation, err := app.ParserReplayMutation(&state, request, result)
		if err != nil {
			t.Fatalf("prepare mutation %d: %v", index, err)
		}
		mutations[index] = mutation
	}

	type applyResult struct {
		id      string
		created bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan applyResult, len(requests))
	var wg sync.WaitGroup
	for index := range requests {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			id, created, err := store.ApplyParserReplay(ctx, requests[index], mutations[index])
			results <- applyResult{id: id, created: created, err: err}
		}(index)
	}
	close(start)
	wg.Wait()
	close(results)

	createdCount := 0
	persistedID := ""
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent replay: %v", result.err)
		}
		if result.created {
			createdCount++
		}
		if persistedID == "" {
			persistedID = result.id
		} else if result.id != persistedID {
			t.Fatalf("concurrent replay IDs = %q and %q", persistedID, result.id)
		}
	}
	if createdCount != 1 {
		t.Fatalf("created results = %d, want exactly one", createdCount)
	}

	state, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load durable state: ok=%v err=%v", ok, err)
	}
	normalizations := 0
	for _, item := range state.Evidence {
		if item.TenantID == tenantID && item.Type == "parser_normalization" {
			normalizations++
			if item.ID != persistedID {
				t.Fatalf("durable parser normalization ID = %q, want %q", item.ID, persistedID)
			}
		}
	}
	if normalizations != 1 {
		t.Fatalf("durable parser normalizations = %d, want 1", normalizations)
	}
	if got := state.Chain[tenantID]; len(got) != 1 || got[0].SubjectID != persistedID {
		t.Fatalf("durable parser replay audit chain = %#v", got)
	}
	focused, ok, err = store.LoadParserReplayState(ctx, tenantID, source.ID, app.ParserVersionScannerAdaptersJSON)
	if err != nil || !ok || len(focused.Evidence) != 2 || focused.Evidence[persistedID].ID != persistedID || len(focused.Chain[tenantID]) != 1 {
		t.Fatalf("focused existing replay marker=%#v chain=%#v ok=%v error=%v", focused.Evidence, focused.Chain, ok, err)
	}
}

func TestStoreApplyParserReplayRejectsForgedExistingMarker(t *testing.T) {
	databaseURL := os.Getenv("EVYDENCE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("EVYDENCE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	admin, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "evydence_parser_replay_forgery_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.pool.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func(cleanupCtx context.Context) {
		_, _ = admin.pool.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE")
	}(context.WithoutCancel(ctx))

	store, err := OpenWithOptions(ctx, databaseURLWithSearchPath(t, databaseURL, schema), StoreOptions{
		LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ApplyMigrations(ctx, "../../../migrations"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	tenantID := "ten_parser_replay_forgery"
	if err := store.ApplyCriticalMutation(ctx, app.CriticalMutation{Tenants: []domain.Tenant{{
		ID: tenantID, Name: "Parser replay forgery", CreatedAt: now,
	}}}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	source := domain.EvidenceItem{
		ID: "ev_parser_forgery_source", TenantID: tenantID, Type: "vulnerability_scan", Subtype: "generic",
		Title: "Parser source", SourceSystem: "scanner", UploadedBy: "collector", ObservedAt: now,
		EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion,
		PayloadRef: "object://tenants/ten_parser_replay_forgery/payloads/source", PayloadHash: "sha256:" + strings.Repeat("a", 64),
		CanonicalHash: "sha256:" + strings.Repeat("b", 64), Canonicalization: domain.CanonicalizationProfileVersion,
		TrustLevel: "L2", VerificationStatus: "pending", CreatedAt: now,
	}
	parserVersion := app.ParserVersionScannerAdaptersJSON
	forged := domain.EvidenceItem{
		ID: "ev_forged_parser_marker", TenantID: tenantID, Type: "parser_normalization", Subtype: "generic",
		Title: "Caller-controlled marker", SourceSystem: "api", UploadedBy: "writer", ObservedAt: now,
		EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion,
		PayloadHash: source.PayloadHash, CanonicalHash: "sha256:" + strings.Repeat("c", 64), Canonicalization: domain.CanonicalizationProfileVersion,
		TrustLevel: "L2", VerificationStatus: "pending",
		Metadata: map[string]any{"replay_of": source.ID, "parser": map[string]any{"version": parserVersion}}, CreatedAt: now,
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, app.ReleaseLedgerMutation{Evidence: []domain.EvidenceItem{source, forged}}); err != nil {
		t.Fatalf("seed forged replay marker: %v", err)
	}

	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_parser","findings":[]}`)
	request := app.ParserReplayRequest{
		TenantID: tenantID, EvidenceID: source.ID, ParserVersion: parserVersion, ActorID: "operator", Now: now.Add(time.Minute),
	}
	state := app.PersistedState{Evidence: map[string]domain.EvidenceItem{source.ID: source}, Chain: map[string][]domain.AuditChainEntry{}}
	result, err := app.ReplayParserEvidence(&state, raw, request)
	if err != nil {
		t.Fatalf("prepare replay: %v", err)
	}
	mutation, err := app.ParserReplayMutation(&state, request, result)
	if err != nil {
		t.Fatalf("prepare mutation: %v", err)
	}

	if id, created, err := store.ApplyParserReplay(ctx, request, mutation); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("ApplyParserReplay = id %q created %v error %v, want conflict", id, created, err)
	}
}
