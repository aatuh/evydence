package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestParserReplayBecomesVisibleToAlreadyRunningLedger(t *testing.T) {
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
	schema := "evydence_parser_visibility_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
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
	tenantID := "ten_" + schema
	if err := store.ApplyCriticalMutation(ctx, app.CriticalMutation{Tenants: []domain.Tenant{{
		ID: tenantID, Name: "Parser visibility", CreatedAt: now,
	}}}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_parser","findings":[]}`)
	source := domain.EvidenceItem{
		ID: "ev_parser_source", TenantID: tenantID, ProductID: "prod_parser", ReleaseID: "rel_parser",
		Type: "vulnerability_scan", Subtype: "generic", Title: "Source scan", SourceSystem: "scanner",
		UploadedBy: "collector_parser", ObservedAt: now, EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion,
		PayloadRef: "object://tenants/" + tenantID + "/payloads/source", PayloadHash: parserProjectionTestDigest(raw),
		PayloadMediaType: "application/json", PayloadSize: int64(len(raw)), CanonicalHash: parserProjectionTestDigest([]byte("source canonical")),
		Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: "L2", VerificationStatus: "pending", CreatedAt: now,
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, app.ReleaseLedgerMutation{
		Products: []domain.Product{{ID: "prod_parser", TenantID: tenantID, Name: "Parser product", Slug: "parser-product", CreatedAt: now}},
		Releases: []domain.Release{{ID: "rel_parser", TenantID: tenantID, ProductID: "prod_parser", Version: "1.0.0", State: "draft", Revision: 1, CreatedAt: now}},
		Evidence: []domain.EvidenceItem{source},
	}); err != nil {
		t.Fatalf("seed source evidence: %v", err)
	}

	ledger, err := newLegacyLedgerFixtureWithContext(ctx, app.Config{APIKeyPepper: "test", Store: store})
	if err != nil {
		t.Fatalf("start API ledger: %v", err)
	}
	replayState, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load replay state ok=%v err=%v", ok, err)
	}
	request := app.ParserReplayRequest{
		TenantID: tenantID, EvidenceID: source.ID, ParserVersion: app.ParserVersionScannerAdaptersJSON,
		ActorID: "operator_parser", Now: now.Add(time.Minute).Add(789 * time.Nanosecond),
	}
	result, err := app.ReplayParserEvidence(&replayState, raw, request)
	if err != nil || !result.Created {
		t.Fatalf("replay parser evidence result=%#v err=%v", result, err)
	}
	mutation, err := app.ParserReplayMutation(&replayState, request, result)
	if err != nil {
		t.Fatalf("build parser replay mutation: %v", err)
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, mutation); err != nil {
		t.Fatalf("append parser replay: %v", err)
	}
	otherTenantID := tenantID + "_other"
	if err := store.ApplyCriticalMutation(ctx, app.CriticalMutation{Tenants: []domain.Tenant{{
		ID: otherTenantID, Name: "Other parser tenant", CreatedAt: now,
	}}}); err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}
	otherSource := source
	otherSource.ID = "ev_parser_source_other"
	otherSource.TenantID = otherTenantID
	otherSource.ProductID = "prod_parser_other"
	otherSource.ReleaseID = "rel_parser_other"
	otherSource.PayloadRef = "object://tenants/" + otherTenantID + "/payloads/source"
	if err := store.ApplyReleaseLedgerMutation(ctx, app.ReleaseLedgerMutation{
		Products: []domain.Product{{ID: otherSource.ProductID, TenantID: otherTenantID, Name: "Other product", Slug: "other-product", CreatedAt: now}},
		Releases: []domain.Release{{ID: otherSource.ReleaseID, TenantID: otherTenantID, ProductID: otherSource.ProductID, Version: "1.0.0", State: "draft", Revision: 1, CreatedAt: now}},
		Evidence: []domain.EvidenceItem{otherSource},
	}); err != nil {
		t.Fatalf("seed other source evidence: %v", err)
	}
	otherState, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		t.Fatalf("load other replay state ok=%v err=%v", ok, err)
	}
	otherRequest := app.ParserReplayRequest{
		TenantID: otherTenantID, EvidenceID: otherSource.ID, ParserVersion: app.ParserVersionScannerAdaptersJSON,
		ActorID: "operator_other", Now: now.Add(2 * time.Minute),
	}
	otherResult, err := app.ReplayParserEvidence(&otherState, raw, otherRequest)
	if err != nil || !otherResult.Created {
		t.Fatalf("replay other parser evidence result=%#v err=%v", otherResult, err)
	}
	otherMutation, err := app.ParserReplayMutation(&otherState, otherRequest, otherResult)
	if err != nil {
		t.Fatalf("build other replay mutation: %v", err)
	}
	if err := store.ApplyReleaseLedgerMutation(ctx, otherMutation); err != nil {
		t.Fatalf("append other parser replay: %v", err)
	}

	projection, err := store.LoadWorkerProjection(ctx, tenantID)
	if err != nil {
		t.Fatalf("load worker projection: %v", err)
	}
	if len(projection.ParserNormalizations) != 1 || projection.ParserNormalizations[0].ID != result.EvidenceID || projection.ParserNormalizations[0].TenantID != tenantID {
		t.Fatalf("parser normalization projection = %#v", projection.ParserNormalizations)
	}
	if projection.ParserNormalizations[0].ID == source.ID {
		t.Fatal("ordinary source evidence leaked into parser-normalization projection")
	}
	otherProjection, err := store.LoadWorkerProjection(ctx, otherTenantID)
	if err != nil {
		t.Fatalf("load other tenant worker projection: %v", err)
	}
	if len(otherProjection.ParserNormalizations) != 1 || otherProjection.ParserNormalizations[0].ID != otherResult.EvidenceID || otherProjection.ParserNormalizations[0].TenantID != otherTenantID {
		t.Fatalf("other parser normalization projection = %#v", otherProjection.ParserNormalizations)
	}

	actor := domain.Actor{TenantID: tenantID, KeyID: "key_parser_reader", Scopes: []string{app.ScopeEvidenceRead}}
	item, err := ledger.GetEvidence(ctx, actor, result.EvidenceID)
	if err != nil || item.ID != result.EvidenceID || item.Type != "parser_normalization" {
		t.Fatalf("GetEvidence item=%#v err=%v", item, err)
	}
	items, err := ledger.ListEvidence(ctx, actor, "rel_parser", "parser_normalization")
	if err != nil || len(items) != 1 || items[0].ID != result.EvidenceID {
		t.Fatalf("ListEvidence items=%#v err=%v", items, err)
	}
}

func parserProjectionTestDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:])
}
