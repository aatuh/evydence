package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

type countingTransparencyFixtureFetcher struct {
	fakeTransparencyProofHTTP
	calls   int
	onFetch func()
}

func (f *countingTransparencyFixtureFetcher) FetchTransparencyProof(ctx context.Context, req app.TransparencyProofRequest) (app.TransparencyProofResult, error) {
	f.calls++
	if f.onFetch != nil {
		f.onFetch()
	}
	if err := ctx.Err(); err != nil {
		return app.TransparencyProofResult{}, err
	}
	return f.fakeTransparencyProofHTTP.FetchTransparencyProof(ctx, req)
}
func transparencyRegressionLedger() (*app.Ledger, *app.MemoryUnitOfWorkFactory, *countingTransparencyFixtureFetcher) {
	factory := app.NewMemoryUnitOfWorkFactory()
	fetcher := &countingTransparencyFixtureFetcher{}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Transparency: fetcher, Now: func() time.Time { return time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) }})
	return ledger, factory, fetcher
}

type transparencyFixtureScope struct {
	operationsFixtureScope
	log        domain.PublicTransparencyLog
	batch      domain.MerkleBatch
	checkpoint domain.TransparencyCheckpoint
	entry      domain.PublicTransparencyLogEntry
}

func seedTransparencyFixtureScope(t *testing.T, ledger *app.Ledger, name string) transparencyFixtureScope {
	t.Helper()
	f := transparencyFixtureScope{operationsFixtureScope: seedOperationsFixtureScope(t, ledger, name)}
	var err error
	f.log, err = ledger.CreatePublicTransparencyLog(t.Context(), f.actor, app.CreatePublicTransparencyLogInput{Name: name, Endpoint: "https://log.example.test", PublicKey: "public-metadata"})
	if err != nil {
		t.Fatal(err)
	}
	f.batch, err = ledger.CreateMerkleBatch(t.Context(), f.actor, app.CreateMerkleBatchInput{})
	if err != nil {
		t.Fatal(err)
	}
	f.checkpoint, err = ledger.CreateTransparencyCheckpoint(t.Context(), f.actor, app.CreateTransparencyCheckpointInput{BatchID: f.batch.ID, Provider: "internal", ExternalID: "checkpoint-" + name})
	if err != nil {
		t.Fatal(err)
	}
	f.entry, err = ledger.PublishPublicTransparencyLogEntry(t.Context(), f.actor, app.PublishPublicTransparencyLogEntryInput{LogID: f.log.ID, CheckpointID: f.checkpoint.ID, ExternalID: "entry-" + name})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func transparencyFixtureHuman(f transparencyFixtureScope) domain.Actor {
	return domain.Actor{TenantID: f.actor.TenantID, UserID: "fixture-human", Scopes: []string{"keys:admin"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: f.actor.TenantID, Scopes: []string{"keys:admin"}}}}
}
func transparencyFixtureProof(f transparencyFixtureScope) string {
	return fmt.Sprintf(`{"root_hash":%q,"leaf_index":0,"tree_size":1,"inclusion_proof":[]}`, f.entry.EntryHash)
}
func transparencyFixtureRequests(f transparencyFixtureScope) []struct {
	name, path, body string
	status           int
} {
	return []struct {
		name, path, body string
		status           int
	}{
		{"log", "/v1/public-transparency-logs", `{"name":" New Log ","endpoint":" https://log.example.test ","public_key":" public-only "}`, 201},
		{"publish", "/v1/public-transparency-log-entries", fmt.Sprintf(`{"log_id":%q,"checkpoint_id":%q,"external_id":"new-external"}`, f.log.ID, f.checkpoint.ID), 201},
		{"verify", "/v1/public-transparency-log-entries/" + f.entry.ID + "/verify", transparencyFixtureProof(f), 200},
		{"fetch", "/v1/public-transparency-log-entries/" + f.entry.ID + "/fetch-proof", `{}`, 200},
	}
}

type failingTransparencyFixture struct {
	transparencyFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingTransparencyFixture) fail(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private transparency failure after write")
}
func (f *failingTransparencyFixture) CreatePublicTransparencyLog(ctx context.Context, a domain.Actor, in e.PublicTransparencyLogInput) (d.PublicTransparencyLog, error) {
	v, err := f.transparencyFixtureCommands.CreatePublicTransparencyLog(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingTransparencyFixture) PublishPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, in e.PublicTransparencyPublicationInput) (d.PublicTransparencyLogEntry, error) {
	v, err := f.transparencyFixtureCommands.PublishPublicTransparencyLogEntry(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingTransparencyFixture) VerifyPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, id string, in e.PublicTransparencyProofInput) (d.PublicTransparencyLogEntry, error) {
	v, err := f.transparencyFixtureCommands.VerifyPublicTransparencyLogEntry(ctx, a, id, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingTransparencyFixture) FetchAndVerifyPublicTransparencyLogEntry(ctx context.Context, a domain.Actor, id string) (d.PublicTransparencyLogEntry, error) {
	v, err := f.transparencyFixtureCommands.FetchAndVerifyPublicTransparencyLogEntry(ctx, a, id)
	return v, f.fail(ctx, v.ID, err)
}

func TestTransparencyFixturesRollBackLogsPublicationProofAuditAndReplayAfterWrite(t *testing.T) {
	for index := 0; index < 4; index++ {
		ledger, factory, fetcher := transparencyRegressionLedger()
		owner := seedTransparencyFixtureScope(t, ledger, "Owner")
		fetcher.result = app.TransparencyProofResult{ExternalID: owner.entry.ExternalID, RootHash: owner.entry.EntryHash, TreeSize: 1}
		request := transparencyFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: transparencyFixtureHuman(owner)}
			commands := &failingTransparencyFixture{transparencyFixtureCommands: transparencyFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.publicTransparencyMetadata, server.publicTransparencyProofs, server.publicTransparencyFetch = commands, commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 500)
			// Assessment IDs are already in the requested URL and its Problem
			// Details instance. They must not appear as a partial result DTO.
			if commands.changedID == "" || !commands.isolated || request.status == 201 && strings.Contains(out, commands.changedID) || strings.Contains(out, fmt.Sprintf(`"id":%q`, commands.changedID)) || strings.Contains(out, `"inclusion_proof_hash"`) || strings.Contains(out, `"data"`) || strings.Contains(out, "private transparency") {
				t.Fatal("partial transparency write bypassed isolation or leaked success")
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("failed replay receipt missing", err)
			}
			for key, receipt := range after.Idempotency {
				if _, exists := before.Idempotency[key]; !exists && (receipt.State != app.IdempotencyFailed || receipt.Status != 0 || receipt.Response != nil) {
					t.Fatal("failed transparency write cached partial success")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed write committed log, publication, assessment, audit or outbox effects")
			}
			wantCalls := 0
			if request.name == "fetch" {
				wantCalls = 1
			}
			if fetcher.calls != wantCalls {
				t.Fatal("failed fetch did not exercise the real provider boundary", fetcher.calls)
			}
		})
	}
}

func TestTransparencyFixturesPreserveCompleteDTOAuditAndCurrentReplayAuthorityWithoutRefetch(t *testing.T) {
	ledger, factory, fetcher := transparencyRegressionLedger()
	owner := seedTransparencyFixtureScope(t, ledger, "Owner")
	foreign := seedTransparencyFixtureScope(t, ledger, "Foreign")
	fetcher.result = app.TransparencyProofResult{ExternalID: owner.entry.ExternalID, RootHash: owner.entry.EntryHash, TreeSize: 1}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := transparencyFixtureHuman(owner)
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	for _, request := range transparencyFixtureRequests(owner) {
		t.Run(request.name, func(t *testing.T) {
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			original := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), request.status)
			id := dataField(t, original, "id")
			after, err := factory.Snapshot()
			if err != nil || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("fresh transparency write lacks single audit and receipt", err)
			}
			var value any
			var hash, auditType string
			switch request.name {
			case "log":
				v := after.PublicTransparencyLogs[id]
				if len(after.PublicTransparencyLogs) != len(before.PublicTransparencyLogs)+1 || v.Name != "New Log" || v.Endpoint != "https://log.example.test" || v.PublicKey != "public-only" || v.State != "configured" {
					t.Fatal("log metadata normalization changed")
				}
				value, auditType = v, "public_transparency_log.created"
			case "publish":
				v := after.PublicTransparencyEntries[id]
				if len(after.PublicTransparencyEntries) != len(before.PublicTransparencyEntries)+1 || v.State != "published" || v.LogID != owner.log.ID || v.CheckpointID != owner.checkpoint.ID || v.MerkleBatchID != owner.batch.ID || v.InclusionVerifiedAt != nil || len(v.VerificationChecks) != 0 {
					t.Fatal("publication acquired unearned proof authority or lost roots")
				}
				value, hash, auditType = v, v.EntryHash, "public_transparency_log_entry.published"
			case "verify", "fetch":
				v := after.PublicTransparencyEntries[id]
				checks := 2
				if request.name == "fetch" {
					checks = 3
					wantRequest := app.TransparencyProofRequest{TenantID: human.TenantID, LogID: owner.log.ID, EntryID: owner.entry.ID, Endpoint: owner.log.Endpoint, ExternalID: owner.entry.ExternalID, EntryHash: owner.entry.EntryHash}
					if fetcher.calls != 1 || fetcher.request != wantRequest {
						t.Fatal("fetch did not bind the owned immutable entry coordinates")
					}
				}
				if len(after.PublicTransparencyEntries) != len(before.PublicTransparencyEntries) || v.State != "inclusion_verified" || v.InclusionVerifiedAt == nil || len(v.VerificationChecks) != checks || len(v.VerificationLimitations) < 2 || v.InclusionRootHash != owner.entry.EntryHash || v.EntryHash != owner.entry.EntryHash {
					t.Fatal("assessment DTO lost complete proof metadata or mutated publication identity")
				}
				value, hash, auditType = v, v.InclusionProofHash, "public_transparency_log_entry.inclusion_verified"
			}
			want, err := json.Marshal(map[string]any{"data": value, "meta": map[string]string{"api_version": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, string(want), original)
			audit := after.AuditEntries[human.TenantID][len(after.AuditEntries[human.TenantID])-1]
			if audit.ActorType != "human_user" || audit.ActorID != human.UserID || audit.TenantID != human.TenantID || audit.SubjectID != id || audit.EntryType != auditType || audit.PayloadHash != hash {
				t.Fatal("transparency audit lost caller or hash attribution")
			}
			fetchCalls := fetcher.calls
			fetcher.err = errors.New("private provider now unavailable")
			assertTrustHTTPReplay(t, original, postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), request.status))
			for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"keys:admin"}}}, {{ResourceType: "tenant", ResourceID: foreign.actor.TenantID, Scopes: []string{"keys:admin"}}}} {
				auth.actor.ResourceGrants = grants
				postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 403)
				postRaw(t, server, "fixture-auth", request.path, "denied-new", []byte(request.body), 403)
			}
			auth.actor = human
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body+" "), 409)
			auth.err = app.ErrUnauthorized
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 401)
			auth.err = nil
			fetcher.err = nil
			latest, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(after, latest) || fetcher.calls != fetchCalls {
				t.Fatal("saved/rejected replay changed state or refetched proof", err)
			}
		})
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][2]string{{owner.log.ID, foreign.log.ID}, {owner.checkpoint.ID, foreign.checkpoint.ID}} {
		request := transparencyFixtureRequests(owner)[1]
		postRaw(t, server, "fixture-auth", request.path, "foreign-publication", []byte(strings.Replace(request.body, field[0], field[1], 1)), 404)
	}
	for _, request := range transparencyFixtureRequests(foreign)[2:] {
		postRaw(t, server, "fixture-auth", request.path, "foreign-entry", []byte(request.body), 404)
	}
	auth.actor.TenantID = "missing-tenant"
	request := transparencyFixtureRequests(owner)[0]
	postRaw(t, server, "fixture-auth", request.path, "missing-owner", []byte(request.body), 403)
	auth.actor = domain.Actor{TenantID: "missing-tenant", KeyID: "fixture-key", Scopes: []string{"keys:admin"}}
	postRaw(t, server, "fixture-auth", request.path, "missing-owner", []byte(request.body), 404)
	auth.actor = human
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || fetcher.calls != 1 {
		t.Fatal("foreign/missing preflight reserved or wrote records or contacted provider", err)
	}
}

func TestTransparencyFixtureGuardsArePureAndCanceledFetchDoesNotCommit(t *testing.T) {
	ledger, factory, fetcher := transparencyRegressionLedger()
	owner := seedTransparencyFixtureScope(t, ledger, "Owner")
	human := transparencyFixtureHuman(owner)
	commands := transparencyFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	proof := e.PublicTransparencyProofInput{RootHash: owner.entry.EntryHash, TreeSize: 1}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []func(context.Context) error{
		func(ctx context.Context) error {
			return commands.AuthorizeCreatePublicTransparencyLog(ctx, human, e.PublicTransparencyLogInput{Name: "Log", Endpoint: owner.log.Endpoint, PublicKey: "public-only"})
		},
		func(ctx context.Context) error {
			return commands.AuthorizePublishPublicTransparencyLogEntry(ctx, human, e.PublicTransparencyPublicationInput{LogID: owner.log.ID, CheckpointID: owner.checkpoint.ID, ExternalID: "new"})
		},
		func(ctx context.Context) error {
			return commands.AuthorizeVerifyPublicTransparencyLogEntry(ctx, human, owner.entry.ID, proof)
		},
		func(ctx context.Context) error {
			return commands.AuthorizeFetchPublicTransparencyLogEntryProof(ctx, human, owner.entry.ID)
		},
	} {
		if err := guard(t.Context()); err != nil {
			t.Fatal("owned preflight failed", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := guard(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("preflight ignored cancellation", err)
		}
	}
	if fetcher.calls != 0 {
		t.Fatal("pure replay guard contacted provider")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fetcher.onFetch = cancel
	if v, err := commands.FetchAndVerifyPublicTransparencyLogEntry(ctx, human, owner.entry.ID); !errors.Is(err, context.Canceled) || v.ID != "" || fetcher.calls != 1 {
		t.Fatal("canceled provider fetch produced an assessment", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("pure guard or canceled fetch persisted proof/audit/replay effects", err)
	}
}

func TestTransparencyFixturesRejectUnusableProviderResultsWithoutCachingSuccess(t *testing.T) {
	for _, mode := range []string{"unavailable", "wrong-external-id", "malformed-proof", "oversized-proof"} {
		t.Run(mode, func(t *testing.T) {
			ledger, factory, fetcher := transparencyRegressionLedger()
			owner := seedTransparencyFixtureScope(t, ledger, "Owner")
			fetcher.result = app.TransparencyProofResult{ExternalID: owner.entry.ExternalID, RootHash: owner.entry.EntryHash, TreeSize: 1}
			switch mode {
			case "unavailable":
				fetcher.err = errors.New("private provider credentials unavailable")
			case "wrong-external-id":
				fetcher.result.ExternalID = "wrong-external-id"
			case "malformed-proof":
				fetcher.result.RootHash = "invalid-provider-proof"
			case "oversized-proof":
				fetcher.result.InclusionProof = make([]string, e.MaxPublicTransparencyProofNodes+1)
			}
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: transparencyFixtureHuman(owner)}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", "/v1/public-transparency-log-entries/"+owner.entry.ID+"/fetch-proof", mode, []byte(`{}`), 422)
			if fetcher.calls != 1 || strings.Contains(out, "private provider") || strings.Contains(out, "wrong-external-id") || strings.Contains(out, "invalid-provider-proof") || strings.Contains(out, `"data"`) || strings.Contains(out, `"verification_checks"`) {
				t.Fatal("unusable provider result acquired trust or exposed provider diagnostics")
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("unusable proof lost failure receipt", err)
			}
			for key, receipt := range after.Idempotency {
				if _, exists := before.Idempotency[key]; !exists && (receipt.State != app.IdempotencyFailed || receipt.Status != 0 || receipt.Response != nil) {
					t.Fatal("unusable proof cached successful authority")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("unusable proof persisted assessment, audit or outbox effects")
			}
		})
	}
}

func TestTransparencyFixturesRecordWellFormedNonmatchingProofAsNotVerified(t *testing.T) {
	for _, fetched := range []bool{false, true} {
		t.Run(fmt.Sprintf("fetched_%t", fetched), func(t *testing.T) {
			ledger, factory, fetcher := transparencyRegressionLedger()
			owner := seedTransparencyFixtureScope(t, ledger, "Owner")
			human := transparencyFixtureHuman(owner)
			proof := e.PublicTransparencyProofInput{LeafHash: "sha256:" + strings.Repeat("b", 64), RootHash: "sha256:" + strings.Repeat("b", 64), TreeSize: 1}
			path := "/v1/public-transparency-log-entries/" + owner.entry.ID + "/verify"
			body := fmt.Sprintf(`{"leaf_hash":%q,"root_hash":%q,"leaf_index":0,"tree_size":1,"inclusion_proof":[]}`, proof.LeafHash, proof.RootHash)
			source, wantCalls := "", 0
			if fetched {
				path = "/v1/public-transparency-log-entries/" + owner.entry.ID + "/fetch-proof"
				body, source, wantCalls = `{}`, "fetched", 1
				fetcher.result = app.TransparencyProofResult{ExternalID: owner.entry.ExternalID, LeafHash: proof.LeafHash, RootHash: proof.RootHash, TreeSize: 1}
			}
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: human}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", path, "nonmatching-proof", []byte(body), 200)
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			v := after.PublicTransparencyEntries[owner.entry.ID]
			if v.State != "inclusion_not_verified" || v.VerificationChecks[0].Result != "failed" || v.VerificationChecks[1].Result != "failed" || len(after.PublicTransparencyEntries) != len(before.PublicTransparencyEntries) || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || len(after.Idempotency) != len(before.Idempotency)+1 || fetcher.calls != wantCalls {
				t.Fatal("well-formed but unbound proof acquired verified authority or lost its assessment")
			}
			expected, err := e.BuildPublicTransparencyVerification(transparencyEntryFixtureModel(owner.entry), proof, source, owner.entry.CreatedAt)
			if err != nil || expected.InclusionProofHash != v.InclusionProofHash {
				t.Fatal("negative proof commitment changed", err)
			}
			want, err := json.Marshal(map[string]any{"data": app.PublicTransparencyVerificationLegacyRecord(expected), "meta": map[string]string{"api_version": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, string(want), out)
			assertTrustHTTPReplay(t, out, postRaw(t, server, "fixture-auth", path, "nonmatching-proof", []byte(body), 200))
			latest, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(after, latest) || fetcher.calls != wantCalls {
				t.Fatal("negative assessment replay changed state or refetched proof", err)
			}
		})
	}
}

func TestBindLedgerPreservesExplicitTransparencyPorts(t *testing.T) {
	first, _ := integrationRegressionLedger()
	second, _ := integrationRegressionLedger()
	metadata, proof, fetch := &transparencyMetadataHTTPFake{}, &transparencyVerificationHTTPFake{}, &transparencyFetchHTTPFake{}
	executor := &decisionHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), first, ServerOptions{PublicTransparencyMetadataCommands: metadata, PublicTransparencyProofCommands: proof, PublicTransparencyFetchCommands: fetch, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	s.bindLegacyLedgerFixture(second)
	if s.publicTransparencyMetadata != metadata || s.publicTransparencyProofs != proof || s.publicTransparencyFetch != fetch || s.durableCommandExecutor != executor {
		t.Fatal("fixture rebinding overwrote explicitly configured transparency ports")
	}
}

func TestTransparencyFixtureMapperPreservesEveryAssessmentFieldWithoutAliasing(t *testing.T) {
	ledger, _, fetcher := transparencyRegressionLedger()
	owner := seedTransparencyFixtureScope(t, ledger, "Owner")
	fetcher.result = app.TransparencyProofResult{ExternalID: owner.entry.ExternalID, RootHash: owner.entry.EntryHash, TreeSize: 1}
	v, err := ledger.FetchAndVerifyPublicTransparencyLogEntry(t.Context(), owner.actor, owner.entry.ID)
	if err != nil || v.InclusionVerifiedAt == nil || len(v.VerificationChecks) != 3 || len(v.VerificationLimitations) != 3 {
		t.Fatal("mapper test lacks complete nested assessment", err)
	}
	want, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	model := transparencyEntryFixtureModel(v)
	got, err := e.EncodePublicTransparencyVerification(model)
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(want), string(got))
	before := transparencyEntryFixtureModel(v)
	model.VerificationChecks[0].Detail, model.VerificationLimitations[0] = "modified", "modified"
	*model.InclusionVerifiedAt = model.InclusionVerifiedAt.AddDate(1, 0, 0)
	if !reflect.DeepEqual(before, transparencyEntryFixtureModel(v)) {
		t.Fatal("assessment mapper aliases stored check, limitation or timestamp")
	}
	in := e.PublicTransparencyProofInput{RootHash: owner.entry.EntryHash, TreeSize: 2, InclusionProof: []string{owner.entry.EntryHash}}
	copy := legacyPublicTransparencyProofInput(in)
	copy.InclusionProof[0] = "modified"
	if !slices.Equal(in.InclusionProof, []string{owner.entry.EntryHash}) {
		t.Fatal("legacy request conversion aliases proof nodes")
	}
}
