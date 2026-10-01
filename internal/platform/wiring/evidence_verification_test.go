package wiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresEvidenceVerificationPreservesCanonicalFieldsAndLegacyOrigins(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('tenant','Evidence'),('foreign','Foreign')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Product','product'),('foreign_product','foreign','Foreign','foreign')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1','draft')`)
	now := time.Now().UTC().Truncate(time.Microsecond)
	item := evidencedomain.EvidenceItem{ID: "evidence", TenantID: "tenant", ReleaseID: "release", Type: "note", Title: "original", SourceSystem: "ci", ObservedAt: now, EvidenceVersion: 1, SchemaVersion: evidencedomain.EvidenceItemSchemaVersion, PayloadRef: "object://private-location", PayloadHash: "sha256:payload", Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion, TrustLevel: "unverified", VerificationStatus: "not_verified", Metadata: map[string]any{"nested": map[string]any{"value": 1}}, SubjectRefs: []evidencedomain.SubjectRef{{Type: "release", ID: "release"}}, CreatedAt: now}
	hash, err := (evidenceCanonicalHasher{}).HashEvidence(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	item.CanonicalHash = hash
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		return repos.Evidence.InsertEvidence(ctx, domain.EvidenceFromContextModel(item))
	}); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildEvidenceVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	points, err := BuildEvidencePointQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := BuildLifecycleEventsQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	readActor := identitydomain.Actor{TenantID: "tenant", KeyID: "reader", Scopes: []string{"evidence:read"}}
	if got, err := points.GetEvidence(ctx, readActor, item.ID); err != nil || got.ID != item.ID {
		t.Fatal("durable evidence point", err)
	}
	if page, err := lifecycle.ListPage(ctx, readActor, item.ID, appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}, nil); err != nil || len(page.Items) != 0 {
		t.Fatal("durable lifecycle", err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"verify:read"}}}}
	result, err := commands.VerifyEvidence(ctx, actor, item.ID)
	if err != nil || result.Result.String() != "passed" || result.Profile.PayloadDigest != hash {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	calls := 0
	run := func(ctx context.Context, _ app.Repositories) (int, any, error) {
		calls++
		result, err := commands.VerifyEvidence(ctx, actor, item.ID)
		return 200, verificationResultToLegacy(result), err
	}
	for i := 0; i < 2; i++ {
		if status, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "evidence-replay", []byte(`{"subject_type":"evidence_item","subject_id":"evidence"}`), run); err != nil || status != 200 {
			t.Fatal("durable replay", err)
		}
	}
	if calls != 1 {
		t.Fatal("durable replay reran command")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL TIME ZONE 'America/New_York'`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	reader := postgresrepositories.New(tx).Verification.(verificationapp.EvidenceVerificationReader)
	subject, err := reader.ResolveEvidenceVerificationSubject(ctx, "tenant", item.ID)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	snapshot, err := reader.ReadEvidenceVerification(ctx, subject)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	tzHash, err := (evidenceCanonicalHasher{}).HashEvidence(ctx, snapshot.Item)
	_ = tx.Rollback(ctx)
	if err != nil || tzHash != hash {
		t.Fatal("session timezone changed canonical hash", err)
	}
	// Relationship/audit/signature projections do not rewrite v2 hash inputs.
	exec(`UPDATE evidence_items SET product_id='product',chain_entry_id='new-chain',signature_refs='["new-signature"]',superseded_by='next',related_evidence_refs='[{"type":"evidence_item","id":"related"}]' WHERE id='evidence'`)
	if _, err := commands.VerifyEvidence(ctx, actor, item.ID); err != nil {
		t.Fatal("v2 hash projection changed", err)
	}
	exec(`UPDATE evidence_items SET title='tampered' WHERE id='evidence'`)
	var before int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM verification_results`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/v1/verify", "evidence-failed", []byte(`{}`), run); !errors.Is(err, verificationapp.ErrVerificationFailed) {
		t.Fatal("failed POST contract", err)
	}
	var after int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM verification_results`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("failed idempotent POST published receipt")
	}
	if result, err := commands.VerifyEvidence(ctx, actor, item.ID); !errors.Is(err, verificationapp.ErrVerificationFailed) || result.Result.String() != "failed" {
		t.Fatal("immutable tampering missed", err)
	}
	exec(`UPDATE evidence_items SET title='original' WHERE id='evidence'`)
	// Legacy canonicalization binds creation relationships; reconstruct them
	// only from the matching v2 origin record, not historical v1 caller details.
	item.Canonicalization = evidencedomain.LegacyEvidenceCanonicalizationProfileVersion
	item.ReleaseID = ""
	item.SubjectRefs = nil
	legacyHash, err := (evidenceCanonicalHasher{}).HashEvidence(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE evidence_items SET canonicalization=$1,canonical_hash=$2,subject_refs=NULL WHERE id='evidence'`, item.Canonicalization, legacyHash)
	exec(`INSERT INTO evidence_lifecycle_events(id,tenant_id,evidence_id,action,reason,details,actor_id,schema_version,created_at) VALUES('origin','tenant','evidence','amendment','link',$1,'actor',$2,$3),('spoof','tenant','evidence','amendment','historical caller',$4,'actor',$5,$3)`, map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{}}, evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, now, map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"release_id": "spoof"}}, evidencedomain.EvidenceLifecycleSchemaVersion)
	if _, err := commands.VerifyEvidence(ctx, actor, item.ID); err != nil {
		t.Fatal("legacy origin compatibility", err)
	}
	exec(`INSERT INTO evidence_lifecycle_events(id,tenant_id,evidence_id,action,reason,details,actor_id,schema_version,created_at) VALUES('conflict','tenant','evidence','amendment','link',$1,'actor',$2,$3)`, map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"release_id": "different"}}, evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, now)
	if result, err := commands.VerifyEvidence(ctx, actor, item.ID); !errors.Is(err, verificationapp.ErrVerificationFailed) || result.Result.String() != "failed" {
		t.Fatal("conflicting origin passed", err)
	}
}

func TestPostgresEvidenceVerificationValidatesParserReplayProvenance(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('tenant','Replay')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	source := domain.EvidenceItem{ID: "source", TenantID: "tenant", Type: "vulnerability_scan", Subtype: "generic", Title: "Source", SourceSystem: "scanner", UploadedBy: "collector", ObservedAt: now, EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadRef: "object://private-payload", PayloadHash: "sha256:" + strings.Repeat("a", 64), Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion, TrustLevel: "L2", VerificationStatus: "pending", CreatedAt: now}
	var err error
	source.CanonicalHash, err = (evidenceCanonicalHasher{}).HashEvidence(ctx, domain.EvidenceToContextModel(source))
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		return repos.Evidence.InsertEvidence(ctx, source)
	}); err != nil {
		t.Fatal(err)
	}
	request := app.ParserReplayRequest{TenantID: "tenant", EvidenceID: source.ID, ParserVersion: app.ParserVersionScannerAdaptersJSON, ActorID: "operator", Now: now.Add(time.Minute)}
	previous := domain.AuditChainEntry{ID: "previous", TenantID: "tenant", Sequence: 1, EntryType: "seed", SubjectType: "tenant", SubjectID: "tenant", ActorType: "operator", ActorID: "operator", OccurredAt: now.Add(789 * time.Nanosecond), SchemaVersion: "audit-chain-entry.v1.0.0"}
	if err := app.RehashAuditChainEntry(&previous); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_chain_entries(id,tenant_id,sequence,entry_type,subject_type,subject_id,actor_type,actor_id,occurred_at,canonical_entry_hash,previous_entry_hash,entry_hash,schema_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, previous.ID, previous.TenantID, previous.Sequence, previous.EntryType, previous.SubjectType, previous.SubjectID, previous.ActorType, previous.ActorID, previous.OccurredAt, previous.CanonicalEntryHash, previous.PreviousEntryHash, previous.EntryHash, previous.SchemaVersion); err != nil {
		t.Fatal(err)
	}
	state := app.PersistedState{Evidence: map[string]domain.EvidenceItem{source.ID: source}, Chain: map[string][]domain.AuditChainEntry{"tenant": {previous}}}
	replay, err := app.ReplayParserEvidence(&state, []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"release","findings":[]}`), request)
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := app.ParserReplayMutation(&state, request, replay)
	if err != nil {
		t.Fatal(err)
	}
	id, created, err := store.ApplyParserReplay(ctx, request, mutation)
	if err != nil || !created {
		t.Fatal("persist replay", id, created, err)
	}
	commands, err := BuildEvidenceVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"verify:read"}}
	points, err := BuildEvidencePointQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := BuildLifecycleEventsQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	readActor := identitydomain.Actor{TenantID: "tenant", KeyID: "reader", Scopes: []string{"evidence:read"}}
	if _, err := commands.VerifyEvidence(ctx, actor, id); err != nil {
		t.Fatal("valid normalization rejected", err)
	}
	assertEvidenceReadProjection(t, ctx, points, lifecycle, readActor, id, nil)
	if _, err := pool.Exec(ctx, `UPDATE audit_chain_entries SET entry_hash='tampered' WHERE id='previous'`); err != nil {
		t.Fatal(err)
	}
	if _, err := commands.VerifyEvidence(ctx, actor, id); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("changed predecessor accepted", err)
	}
	assertEvidenceReadProjection(t, ctx, points, lifecycle, readActor, id, evidencequery.ErrConflict)
	if _, err := pool.Exec(ctx, `UPDATE audit_chain_entries SET entry_hash=$1 WHERE id='previous'`, previous.EntryHash); err != nil {
		t.Fatal(err)
	}
	var item domain.EvidenceItem
	for _, value := range mutation.Evidence {
		if value.ID == id {
			item = value
		}
	}
	// Rehash a modified row: hash correctness must not replace provenance.
	item.Title = "forged title"
	hash, err := (evidenceCanonicalHasher{}).HashEvidence(ctx, domain.EvidenceToContextModel(item))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE evidence_items SET title=$1,canonical_hash=$2 WHERE id=$3`, item.Title, hash, id); err != nil {
		t.Fatal(err)
	}
	if _, err := commands.VerifyEvidence(ctx, actor, id); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("forged normalization passed", err)
	}
	assertEvidenceReadProjection(t, ctx, points, lifecycle, readActor, id, evidencequery.ErrConflict)
	item.Title = "Parser normalization replay"
	hash, err = (evidenceCanonicalHasher{}).HashEvidence(ctx, domain.EvidenceToContextModel(item))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE evidence_items SET title=$1,canonical_hash=$2 WHERE id=$3`, item.Title, hash, id); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE audit_chain_entries SET actor_id='forged' WHERE id=$1`, item.ChainEntryID); err != nil {
		t.Fatal(err)
	}
	if _, err := commands.VerifyEvidence(ctx, actor, id); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("forged linked audit passed", err)
	}
	assertEvidenceReadProjection(t, ctx, points, lifecycle, readActor, id, evidencequery.ErrConflict)
	if _, err := pool.Exec(ctx, `UPDATE audit_chain_entries SET actor_id='operator' WHERE id=$1`, item.ChainEntryID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE evidence_items SET payload_ref='object://changed-source' WHERE id='source'`); err != nil {
		t.Fatal(err)
	}
	if _, err := commands.VerifyEvidence(ctx, actor, id); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("changed source provenance passed", err)
	}
	assertEvidenceReadProjection(t, ctx, points, lifecycle, readActor, id, evidencequery.ErrConflict)
}

func TestPostgresEvidenceVerificationLocksCanonicalOriginPublication(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('tenant','Origins'); INSERT INTO evidence_items(id,tenant_id,type,title,source_system,observed_at,evidence_version,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,chain_entry_id) VALUES('evidence','tenant','note','Note','ci',now(),1,'evidence-item.v1.0.0','hash','hash','legacy','L2','pending','')`); err != nil {
		t.Fatal(err)
	}
	err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		reader := repos.Verification.(verificationapp.EvidenceVerificationReader)
		if _, err := reader.ResolveEvidenceVerificationSubject(ctx, "tenant", "evidence"); err != nil {
			return err
		}
		other, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = other.Rollback(ctx) }()
		if _, err := other.Exec(ctx, `SET LOCAL lock_timeout='50ms'`); err != nil {
			return err
		}
		repositories := postgresrepositories.New(other)
		event := domain.EvidenceLifecycleEvent{ID: "origin", TenantID: "tenant", EvidenceID: "evidence", Action: "amendment", Reason: "link", ActorID: "actor", SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, CreatedAt: time.Now(), Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{}}}
		err = repositories.Evidence.AppendLifecycle(ctx, event)
		var locked *pgconn.PgError
		if !errors.As(err, &locked) || locked.Code != "55P03" {
			t.Fatalf("canonical origin changed during locked verification: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPostgresEvidenceVerificationValidatesSelectedWorkerFacts(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('tenant','Verify')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Product','product')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name) VALUES('project','tenant','product','Project')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1','draft')`)
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version) VALUES('build','tenant','project','release','github','commit','succeeded',now(),'[]','build-run.v1.0.0')`)
	now := time.Now().UTC().Truncate(time.Microsecond)
	commands, err := BuildEvidenceVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"verify:read"}}
	points, err := BuildEvidencePointQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := BuildLifecycleEventsQuery(store)
	if err != nil {
		t.Fatal(err)
	}
	readActor := identitydomain.Actor{TenantID: "tenant", KeyID: "reader", Scopes: []string{"evidence:read"}}
	for _, tc := range []struct{ kind, insert, poison string }{
		{"sbom", `INSERT INTO sboms(id,tenant_id,evidence_id,release_id,format,spec_version,component_count,components) VALUES('parsed_sbom','tenant','sbom','release','cyclonedx','1.6',1,'[{"name":"component"}]')`, `UPDATE sboms SET component_count=2 WHERE id='parsed_sbom'`},
		{"vulnerability_scan", `INSERT INTO vulnerability_scans(id,tenant_id,evidence_id,release_id,scanner,adapter,adapter_version,source_schema,target_ref,summary,findings) VALUES('parsed_scan','tenant','vulnerability_scan','release','generic','generic','1','scan.v1','target','{}','[{"id":"f","vulnerability":"CVE-TEST"}]')`, `UPDATE vulnerability_scans SET findings='[{"id":"f","vulnerability":"CVE-TEST"},{"id":"f","vulnerability":"CVE-TEST"}]' WHERE id='parsed_scan'`},
		{"openapi_contract", `INSERT INTO openapi_contracts(id,tenant_id,evidence_id,product_id,release_id,version,hash,path_count) VALUES('parsed_contract','tenant','openapi_contract','product','release','3.1.0','sha256:hash',0)`, `UPDATE openapi_contracts SET version='' WHERE id='parsed_contract'`},
		{"vex", `INSERT INTO vex_documents(id,tenant_id,evidence_id,release_id,format,author,statement_count,status_summary,schema_version) VALUES('parsed_vex','tenant','vex','release','openvex','author',0,'{}','vex.v1')`, `UPDATE vex_documents SET release_id='foreign' WHERE id='parsed_vex'`},
		{"build_attestation", `INSERT INTO build_attestations(id,tenant_id,evidence_id,build_id,payload_hash,payload_size,payload_type,predicate_type,subject_digests,materials_count,signature_count,verification_status,schema_version) VALUES('parsed_attestation','tenant','build_attestation','build','sha256:hash',0,'','','[]',0,0,'accepted','attestation.v1')`, `UPDATE build_attestations SET verification_status='structurally_valid' WHERE id='parsed_attestation'`},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			item := evidencedomain.EvidenceItem{ID: tc.kind, TenantID: "tenant", ProductID: "product", ReleaseID: "release", Type: tc.kind, Title: "upload", SourceSystem: "ci", ObservedAt: now, EvidenceVersion: 1, SchemaVersion: evidencedomain.EvidenceItemSchemaVersion, PayloadHash: "sha256:payload", Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion, TrustLevel: "L2", VerificationStatus: "pending", CreatedAt: now}
			if tc.kind == "build_attestation" {
				item.BuildID = "build"
			}
			item.CanonicalHash, err = (evidenceCanonicalHasher{}).HashEvidence(ctx, item)
			if err != nil {
				t.Fatal(err)
			}
			if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
				return repos.Evidence.InsertEvidence(ctx, domain.EvidenceFromContextModel(item))
			}); err != nil {
				t.Fatal(err)
			}
			// Canonical verification does not require a queued parser to finish.
			if _, err := commands.VerifyEvidence(ctx, actor, item.ID); err != nil {
				t.Fatal("queued evidence", err)
			}
			assertEvidenceReadProjection(t, ctx, points, lifecycle, readActor, item.ID, nil)
			exec(tc.insert)
			if _, err := commands.VerifyEvidence(ctx, actor, item.ID); err != nil {
				t.Fatal("parsed evidence", err)
			}
			assertEvidenceReadProjection(t, ctx, points, lifecycle, readActor, item.ID, nil)
			exec(tc.poison)
			if _, err := commands.VerifyEvidence(ctx, actor, item.ID); !errors.Is(err, verificationapp.ErrConflict) {
				t.Fatal("poisoned projection accepted", err)
			}
			assertEvidenceReadProjection(t, ctx, points, lifecycle, readActor, item.ID, evidencequery.ErrConflict)
		})
	}
	// An unrelated poisoned projection must not trigger tenant-wide loading.
	item := evidencedomain.EvidenceItem{ID: "note", TenantID: "tenant", Type: "note", Title: "Note", SourceSystem: "ci", EvidenceVersion: 1, SchemaVersion: evidencedomain.EvidenceItemSchemaVersion, PayloadHash: "sha256:payload", TrustLevel: "L2", VerificationStatus: "pending", ObservedAt: now, CreatedAt: now, Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion}
	item.CanonicalHash, err = (evidenceCanonicalHasher{}).HashEvidence(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		return repos.Evidence.InsertEvidence(ctx, domain.EvidenceFromContextModel(item))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := commands.VerifyEvidence(ctx, actor, item.ID); err != nil {
		t.Fatal("unrelated tenant state loaded", err)
	}
	assertEvidenceReadProjection(t, ctx, points, lifecycle, readActor, item.ID, nil)
}

func assertEvidenceReadProjection(t *testing.T, ctx context.Context, points *evidencequery.EvidencePoints, lifecycle *evidencequery.LifecycleEvents, actor identitydomain.Actor, id string, wantErr error) {
	t.Helper()
	item, err := points.GetEvidence(ctx, actor, id)
	if !errors.Is(err, wantErr) || (wantErr == nil && (item.ID != id || item.TenantID != actor.TenantID)) || (wantErr != nil && item.ID != "") {
		t.Fatalf("evidence point id=%q want error=%v got=%#v error=%v", id, wantErr, item, err)
	}
	page, err := lifecycle.ListPage(ctx, actor, id, appquery.PageRequest{PageSize: 1, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}, nil)
	if !errors.Is(err, wantErr) || len(page.Items) != 0 || page.Next != nil {
		t.Fatalf("lifecycle id=%q want error=%v got=%#v error=%v", id, wantErr, page, err)
	}
}

func TestPostgresEvidenceVerificationAuthorizesBeforePayloadAndRollsBack(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('tenant','Verify'),('foreign','Foreign')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Product','product')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1','draft')`)
	exec(`INSERT INTO evidence_items(id,tenant_id,release_id,type,title,source_system,observed_at,evidence_version,schema_version,payload_hash,canonical_hash,canonicalization,trust_level,verification_status,chain_entry_id,metadata) VALUES('evidence','tenant','release','note','Note','ci',now(),1,'evidence-item.v1.0.0','hash','hash','evydence-c14n.v2.0.0','L2','pending','',$1),('foreign','foreign',NULL,'note','Note','ci',now(),1,'evidence-item.v1.0.0','hash','hash','evydence-c14n.v2.0.0','L2','pending','','{}')`, map[string]any{"oversized": strings.Repeat("x", verificationapp.MaxEvidenceVerificationBytes)})
	commands, err := BuildEvidenceVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"verify:read"}}
	if _, err := commands.VerifyEvidence(ctx, actor, "evidence"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("read oversized payload before authorizing", err)
	}
	actor.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"verify:read"}}}
	if _, err := commands.VerifyEvidence(ctx, actor, "foreign"); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal("foreign evidence", err)
	}
	if _, err := commands.VerifyEvidence(ctx, actor, "evidence"); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("unbounded metadata accepted", err)
	}
	exec(`UPDATE evidence_items SET metadata='{}' WHERE id='evidence'`)
	exec(`CREATE FUNCTION reject_evidence_verify_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced audit failure';END$$`)
	exec(`CREATE TRIGGER reject_evidence_verify_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_evidence_verify_audit()`)
	if result, err := commands.VerifyEvidence(ctx, actor, "evidence"); err == nil || result.ID != "" {
		t.Fatal("partial result published", err)
	}
	var receipts, audits, jobs int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM verification_results),(SELECT count(*) FROM audit_chain_entries),(SELECT count(*) FROM outbox_jobs)`).Scan(&receipts, &audits, &jobs); err != nil {
		t.Fatal(err)
	}
	if receipts+audits+jobs != 0 {
		t.Fatal("partial effects committed", receipts, audits, jobs)
	}
	if _, err := BuildEvidenceVerificationCommands(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
}

func TestPostgresEvidenceVerificationBoundsCanonicalOrigins(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('tenant','Origins')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	item := evidencedomain.EvidenceItem{ID: "evidence", TenantID: "tenant", Type: "note", Title: "Note", SourceSystem: "ci", ObservedAt: now, CreatedAt: now, EvidenceVersion: 1, SchemaVersion: evidencedomain.EvidenceItemSchemaVersion, PayloadHash: "sha256:payload", Canonicalization: evidencedomain.LegacyEvidenceCanonicalizationProfileVersion, TrustLevel: "L2", VerificationStatus: "pending"}
	var err error
	item.CanonicalHash, err = (evidenceCanonicalHasher{}).HashEvidence(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		return repos.Evidence.InsertEvidence(ctx, domain.EvidenceFromContextModel(item))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO evidence_lifecycle_events(id,tenant_id,evidence_id,action,reason,details,actor_id,schema_version,created_at) SELECT 'origin_'||n,'tenant','evidence','amendment','link',jsonb_build_object($1::text,'{}'::jsonb),'actor',$2,now() FROM generate_series(1,4097)n`, evidencedomain.LegacyCanonicalOriginDetailKey, evidencedomain.EvidenceRelationshipLifecycleSchemaVersion); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildEvidenceVerificationCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"verify:read"}}
	if _, err := commands.VerifyEvidence(ctx, actor, item.ID); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("too many canonical origins accepted", err)
	}
	// Each row fits the byte limit, but the combined selected JSON must not.
	if _, err := pool.Exec(ctx, `DELETE FROM evidence_lifecycle_events WHERE id='origin_4097'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE evidence_lifecycle_events SET details=jsonb_build_object($1::text,jsonb_build_object('ignored',repeat('x',2100)))`, evidencedomain.LegacyCanonicalOriginDetailKey); err != nil {
		t.Fatal(err)
	}
	if _, err := commands.VerifyEvidence(ctx, actor, item.ID); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("aggregate origin bytes accepted", err)
	}
	var receipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM verification_results`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 0 {
		t.Fatal("overflow published receipt")
	}
}
