package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type failingIntegrationFixture struct {
	integrationFixtureCommands
	changedID, secret string
	isolated          bool
}

func (f *failingIntegrationFixture) failure(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private integration failure after write")
}
func (f *failingIntegrationFixture) CreateCollector(ctx context.Context, a domain.Actor, in integrationapp.CreateCollectorInput) (integrationdomain.Collector, identitydomain.APIKey, string, error) {
	v, key, secret, err := f.integrationFixtureCommands.CreateCollector(ctx, a, in)
	f.secret = secret
	return v, key, secret, f.failure(ctx, v.ID, err)
}
func (f *failingIntegrationFixture) RecordCollectorRelease(ctx context.Context, a domain.Actor, in integrationapp.RecordCollectorReleaseInput) (integrationdomain.CollectorRelease, error) {
	v, err := f.integrationFixtureCommands.RecordCollectorRelease(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIntegrationFixture) CreateCommercialCollectorDefinition(ctx context.Context, a domain.Actor, in integrationapp.CreateCommercialCollectorInput) (integrationdomain.CommercialCollectorDefinition, error) {
	v, err := f.integrationFixtureCommands.CreateCommercialCollectorDefinition(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIntegrationFixture) CreateSourceRepository(ctx context.Context, a domain.Actor, in integrationapp.CreateSourceRepositoryInput) (integrationdomain.SourceRepository, error) {
	v, err := f.integrationFixtureCommands.CreateSourceRepository(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIntegrationFixture) RecordSourceCommit(ctx context.Context, a domain.Actor, in integrationapp.RecordSourceCommitInput) (integrationdomain.SourceCommit, error) {
	v, err := f.integrationFixtureCommands.RecordSourceCommit(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIntegrationFixture) UpsertSourceBranch(ctx context.Context, a domain.Actor, in integrationapp.UpsertSourceBranchInput) (integrationdomain.SourceBranch, error) {
	v, err := f.integrationFixtureCommands.UpsertSourceBranch(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIntegrationFixture) RecordPullRequest(ctx context.Context, a domain.Actor, in integrationapp.RecordPullRequestInput) (integrationdomain.PullRequest, error) {
	v, err := f.integrationFixtureCommands.RecordPullRequest(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingIntegrationFixture) RecordSourceSnapshot(ctx context.Context, a domain.Actor, provider string, in integrationapp.SourceSnapshotInput) (integrationapp.SourceSnapshotResult, error) {
	v, err := f.integrationFixtureCommands.RecordSourceSnapshot(ctx, a, provider, in)
	return v, f.failure(ctx, v.Repository.ID, err)
}

type integrationFixtureScope struct {
	actor      domain.Actor
	product    domain.Product
	project    domain.Project
	repository domain.SourceRepository
	head       domain.SourceCommit
	collector  domain.Collector
}

func seedIntegrationFixtureScope(t *testing.T, ledger *app.Ledger, name string) integrationFixtureScope {
	t.Helper()
	var f integrationFixtureScope
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), name, "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	f.actor, err = ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	f.product, err = ledger.CreateProduct(t.Context(), f.actor, name, strings.ToLower(name))
	if err != nil {
		t.Fatal(err)
	}
	f.project, err = ledger.CreateProject(t.Context(), f.actor, f.product.ID, name)
	if err != nil {
		t.Fatal(err)
	}
	f.repository, err = ledger.CreateSourceRepository(t.Context(), f.actor, app.CreateRepositoryInput{ProjectID: f.project.ID, Provider: "github", FullName: "fixture/" + name, DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	f.head, err = ledger.RecordSourceCommit(t.Context(), f.actor, app.RecordCommitInput{RepositoryID: f.repository.ID, SHA: strings.Repeat("a", 40), Message: " original message "})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ledger.UpsertSourceBranch(t.Context(), f.actor, app.UpsertBranchInput{RepositoryID: f.repository.ID, Name: "main", HeadCommitID: f.head.ID, Protected: true, ProtectionHash: "original"})
	if err != nil {
		t.Fatal(err)
	}
	f.collector, _, _, err = ledger.CreateCollector(t.Context(), f.actor, app.CreateCollectorInput{Name: name, Type: "generic_ci", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ledger.RecordCollectorRelease(t.Context(), f.actor, app.RecordCollectorReleaseInput{CollectorID: f.collector.ID, Version: "1", ArtifactDigest: "sha256:" + strings.Repeat("a", 64), Pinned: true})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type integrationFixtureRequest struct{ name, path, body string }

func integrationFixtureRequests(f integrationFixtureScope) []integrationFixtureRequest {
	return []integrationFixtureRequest{
		{"collector", "/v1/collectors", `{"name":"New builder","type":"generic_ci","version":"2","scopes":["evidence:write"]}`},
		{"collector-release", "/v1/collectors/" + f.collector.ID + "/releases", `{"version":"2","artifact_digest":"sha256:` + strings.Repeat("b", 64) + `","pinned":true}`},
		{"commercial", "/v1/commercial-collectors", `{"name":"Scanner","provider":"provider","version":"2","manifest_hash":"sha256:` + strings.Repeat("b", 64) + `","allowed_scopes":["evidence:write"]}`},
		{"repository", "/v1/source/repositories", fmt.Sprintf(`{"project_id":%q,"provider":"github","full_name":"fixture/new"}`, f.project.ID)},
		{"commit", "/v1/source/commits", fmt.Sprintf(`{"repository_id":%q,"sha":%q,"author":"Fixture Team","message":" exact message \u0000 "}`, f.repository.ID, strings.Repeat("b", 40))},
		{"branch", "/v1/source/branches", fmt.Sprintf(`{"repository_id":%q,"name":"main","head_commit_id":%q,"protected":false}`, f.repository.ID, f.head.ID)},
		{"pull-request", "/v1/source/pull-requests", fmt.Sprintf(`{"repository_id":%q,"provider":"github","provider_id":"42","title":"Change","state":"open","head_commit_id":%q}`, f.repository.ID, f.head.ID)},
		{"github-snapshot", "/v1/collectors/github/source-snapshots", fmt.Sprintf(`{"project_id":%q,"repository":{"full_name":"fixture/snapshot","clone_url":"https://example.invalid/source.git","default_branch":"main"},"commit":{"sha":%q,"message":" exact snapshot \u0000 "},"branch":{"name":"main","protected":true,"protection_hash":"opaque"},"pull_request":{"provider_id":"43","title":"Snapshot","state":"open"}}`, f.project.ID, strings.Repeat("c", 40))},
		{"gitlab-snapshot", "/v1/collectors/gitlab/source-snapshots", fmt.Sprintf(`{"project_id":%q,"repository":{"full_name":"fixture/snapshot"},"commit":{"sha":%q},"branch":{"name":"main"},"pull_request":{"provider_id":"44","title":"Snapshot","state":"merged"}}`, f.project.ID, strings.Repeat("d", 40))},
	}
}

func integrationRegressionLedger() (*app.Ledger, *app.MemoryUnitOfWorkFactory) {
	factory := app.NewMemoryUnitOfWorkFactory()
	return newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: func() time.Time { return time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) }}), factory
}

func TestIntegrationFixturesRollBackCredentialsPinsSourceChildrenAndAudit(t *testing.T) {
	for index := 0; index < 9; index++ {
		ledger, factory := integrationRegressionLedger()
		owner := seedIntegrationFixtureScope(t, ledger, "Owner")
		request := integrationFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: owner.actor}
			commands := &failingIntegrationFixture{integrationFixtureCommands: integrationFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.collectorCommands, server.sourceRepositoryCommands, server.sourceCommitCommands = commands, commands, commands
			server.sourceBranchCommands, server.pullRequestCommands, server.sourceSnapshotCommands = commands, commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, commands.changedID) || strings.Contains(out, "private integration") || commands.secret != "" && strings.Contains(out, commands.secret) {
				t.Fatal("failed integration write bypassed isolation or exposed partial metadata/secret")
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("missing failed receipt", err)
			}
			for key, receipt := range after.Idempotency {
				if _, exists := before.Idempotency[key]; !exists && (receipt.State != app.IdempotencyFailed || receipt.Status != 0 || receipt.Response != nil) {
					t.Fatal("partial success retained")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed integration write committed key, collector, pin, source child, audit, or job effects")
			}
		})
	}
}

func TestIntegrationFixturesReplayMetadataWithoutSecretsOrRepeatedEffects(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedIntegrationFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	auth := &configuredAuthenticator{actor: owner.actor}
	server.authn = auth
	for _, request := range integrationFixtureRequests(owner) {
		t.Run(request.name, func(t *testing.T) {
			original := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201)
			var oneTime string
			if request.name == "collector" {
				var envelope map[string]any
				if err := json.Unmarshal([]byte(original), &envelope); err != nil {
					t.Fatal(err)
				}
				data := envelope["data"].(map[string]any)
				oneTime, _ = data["secret"].(string)
				if oneTime == "" {
					t.Fatal("initial one-time collector credential missing")
				}
				delete(data, "secret")
				encoded, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				original = string(encoded)
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			replay := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201)
			assertTrustHTTPReplay(t, original, replay)
			if oneTime != "" {
				if strings.Contains(replay, oneTime) || strings.Contains(replay, `"secret"`) || strings.Contains(replay, `"hash"`) {
					t.Fatal("collector replay exposed credentials")
				}
				for _, receipt := range before.Idempotency {
					encoded, err := json.Marshal(receipt.Response)
					if err != nil || strings.Contains(string(encoded), oneTime) {
						t.Fatal("durable receipt retained collector secret", err)
					}
				}
			}
			auth.actor.Scopes = nil
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 403)
			auth.actor = owner.actor
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body+" "), 409)
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("completed/rejected integration replay repeated effects", err)
			}
		})
	}
}
