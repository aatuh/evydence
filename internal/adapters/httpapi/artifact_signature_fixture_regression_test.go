package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type signatureFixtureStore struct {
	*filesystem.Store
	stages int
}

func (s *signatureFixtureStore) StagePayload(ctx context.Context, p app.ObjectPayload, r io.Reader) (app.ObjectPayload, error) {
	s.stages++
	return s.Store.StagePayload(ctx, p, r)
}
func signatureRegressionLedger(t *testing.T) (*app.Ledger, *app.MemoryUnitOfWorkFactory, *signatureFixtureStore) {
	t.Helper()
	store, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &signatureFixtureStore{Store: store}
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, ObjectStore: objects, Now: func() time.Time { return time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) }})
	return ledger, factory, objects
}

type signatureFixtureScope struct {
	evidenceFixtureScope
	artifact domain.Artifact
}

func seedSignatureFixtureScope(t *testing.T, ledger *app.Ledger, name string) signatureFixtureScope {
	t.Helper()
	f := signatureFixtureScope{evidenceFixtureScope: seedEvidenceFixtureScope(t, ledger, name)}
	var err error
	f.artifact, err = ledger.RegisterArtifact(t.Context(), f.actor, "api.tar", "application/octet-stream", "sha256:"+strings.Repeat("c", 64), 42)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.CreateEvidence(t.Context(), f.actor, app.CreateEvidenceInput{ProductID: f.product.ID, Type: "manual", Title: "Artifact association", PayloadHash: "sha256:" + strings.Repeat("d", 64), SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: f.artifact.ID, Digest: f.artifact.Digest}}}); err != nil {
		t.Fatal(err)
	}
	return f
}
func signatureFixtureBody(f signatureFixtureScope, payload bool) string {
	optional := ""
	if payload {
		optional = `,"payload":{"private_marker":"raw-signature-payload-fixture"},"payload_media_type":"application/json"`
	}
	return fmt.Sprintf(`{"artifact_id":%q,"algorithm":"cosign","key_id":"public-key","signature":"opaque-recorded-signature"%s}`, f.artifact.ID, optional)
}

type failingSignatureFixture struct {
	artifactSignatureFixture
	changedID string
	isolated  bool
}

func (f *failingSignatureFixture) CreateArtifactSignature(ctx context.Context, a domain.Actor, in verificationapp.CreateArtifactSignatureInput) (verificationdomain.ArtifactSignature, error) {
	v, err := f.artifactSignatureFixture.CreateArtifactSignature(ctx, a, in)
	if err != nil {
		return v, err
	}
	f.changedID, f.isolated = v.ID, f.commandLedger(ctx) != f.ledger
	return v, errors.New("private signature fixture failure after write")
}
func TestArtifactSignatureFixtureRollsBackSignaturePayloadMetadataAuditJobAndReplay(t *testing.T) {
	for _, payload := range []bool{false, true} {
		t.Run(fmt.Sprintf("payload_%t", payload), func(t *testing.T) {
			ledger, factory, objects := signatureRegressionLedger(t)
			owner := seedSignatureFixtureScope(t, ledger, "Owner")
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: owner.actor}
			commands := &failingSignatureFixture{artifactSignatureFixture: artifactSignatureFixture{catalogFixtureCommands{ledger: ledger}}}
			server.artifactSignatureCommands = commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", "/v1/artifact-signatures", "failure", []byte(signatureFixtureBody(owner, payload)), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, commands.changedID) || strings.Contains(out, `"data"`) || strings.Contains(out, "private signature") || strings.Contains(out, "raw-signature-payload") {
				t.Fatal("partial signature effects leaked or bypassed isolation")
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("failed signature receipt missing", err)
			}
			for key, record := range after.Idempotency {
				if _, exists := before.Idempotency[key]; !exists && (record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil) {
					t.Fatal("partial signature success cached")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("signature failure committed signature/payload metadata/audit/job effects")
			}
			wantStages := 0
			if payload {
				wantStages = 1
			}
			if objects.stages != wantStages {
				t.Fatal("signature rollback test did not exercise actual optional staging", objects.stages)
			}
			if payload {
				raw := []byte(`{"private_marker":"raw-signature-payload-fixture"}`)
				digest := app.BytesPayloadSource(raw).Digest
				staging, final, err := app.CanonicalObjectPayloadKeys(owner.actor.TenantID, digest)
				if err != nil {
					t.Fatal(err)
				}
				staged, err := objects.Get(t.Context(), staging)
				if err != nil || !reflect.DeepEqual(staged.Bytes, raw) || staged.Digest != digest {
					t.Fatal("rollback fixture did not retain exact unreferenced staged bytes", err)
				}
				if _, err := objects.Get(t.Context(), final); !errors.Is(err, app.ErrNotFound) {
					t.Fatal("failed signature finalized its staged payload", err)
				}
			}
		})
	}
}
func TestArtifactSignatureFixtureReplayAndReadsKeepCurrentAuthorityAndPublicMetadata(t *testing.T) {
	ledger, factory, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	foreign := seedSignatureFixtureScope(t, ledger, "Foreign")
	foreignSignature, err := ledger.CreateArtifactSignature(t.Context(), foreign.actor, app.CreateArtifactSignatureInput{ArtifactID: foreign.artifact.ID, Algorithm: "cosign", Signature: "foreign-recorded-signature"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "reviewer", Scopes: []string{"evidence:read", "evidence:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"evidence:read", "evidence:write"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	for _, payload := range []bool{false, true} {
		body, key := signatureFixtureBody(owner, payload), fmt.Sprintf("payload-%t", payload)
		prior, err := factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		original := postRaw(t, server, "fixture-auth", "/v1/artifact-signatures", key, []byte(body), 201)
		if strings.Contains(original, "raw-signature-payload") || strings.Contains(original, "private_marker") {
			t.Fatal("recorded signature disclosed raw payload")
		}
		var response struct {
			Data domain.ArtifactSignature `json:"data"`
		}
		if err := json.Unmarshal([]byte(original), &response); err != nil || response.Data.ID == "" || response.Data.TenantID != human.TenantID || response.Data.ArtifactID != owner.artifact.ID || response.Data.SubjectDigest != owner.artifact.Digest || response.Data.Signature != "opaque-recorded-signature" || response.Data.KeyID != "public-key" || response.Data.VerificationStatus != "recorded" || response.Data.SchemaVersion != domain.ArtifactSignatureSchemaVersion {
			t.Fatal("signature DTO lost recorded public fields", err)
		}
		if payload != (response.Data.PayloadRef != "" && response.Data.PayloadHash != "") {
			t.Fatalf("optional signature payload metadata lost: payload=%t response=%s", payload, original)
		}
		before, err := factory.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		wantPayloads, wantJobs := len(prior.ObjectPayloads), len(prior.OutboxJobs)
		if payload {
			wantPayloads++
			wantJobs++
		}
		if len(before.ObjectPayloads) != wantPayloads || len(before.OutboxJobs) != wantJobs {
			t.Fatal("signature staging lost atomic payload metadata or finalization job")
		}
		stages := objects.stages
		entries := before.AuditEntries[human.TenantID]
		entry := entries[len(entries)-1]
		if entry.ActorType != "human_user" || entry.ActorID != human.UserID || entry.SubjectID != response.Data.ID || entry.PayloadHash != owner.artifact.Digest {
			t.Fatal("signature audit lost actual principal/digest binding", entry)
		}
		assertTrustHTTPReplay(t, original, postRaw(t, server, "fixture-auth", "/v1/artifact-signatures", key, []byte(body), 201))
		path := "/v1/artifact-signatures/" + response.Data.ID
		out := getRaw(t, server, "fixture-auth", path, 200)
		assertTrustHTTPReplay(t, original, out.Body.String())
		getRaw(t, server, "fixture-auth", "/v1/artifact-signatures/"+foreignSignature.ID, 404)
		for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}}} {
			auth.actor.ResourceGrants = grants
			postRaw(t, server, "fixture-auth", "/v1/artifact-signatures", key, []byte(body), 403)
			getRaw(t, server, "fixture-auth", path, 403)
		}
		auth.actor = human
		postRaw(t, server, "fixture-auth", "/v1/artifact-signatures", key, []byte(body+" "), 409)
		auth.actor.TenantID = foreign.actor.TenantID
		auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: foreign.actor.TenantID, Scopes: []string{"*"}}}
		postRaw(t, server, "fixture-auth", "/v1/artifact-signatures", key, []byte(body), 404)
		getRaw(t, server, "fixture-auth", path, 404)
		auth.actor = human
		after, err := factory.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("signature read/replay/denial added effects", err)
		}
		if objects.stages != stages {
			t.Fatal("signature replay/read/denial restaged raw payload")
		}
	}
	fixture := artifactSignatureFixture{catalogFixtureCommands{ledger: ledger}}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	in := verificationapp.CreateArtifactSignatureInput{ArtifactID: owner.artifact.ID, Algorithm: "cosign", Signature: "opaque-recorded-signature"}
	if err := fixture.AuthorizeArtifactSignatureCreation(t.Context(), human, in); err != nil {
		t.Fatal(err)
	}
	if err := fixture.AuthorizeArtifactSignatureCreation(cancelled, human, in); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled signature guard accepted", err)
	}
	if _, err := fixture.GetArtifactSignature(cancelled, human, foreignSignature.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled signature point read accepted", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("signature guard/cancellation changed state", err)
	}
}
