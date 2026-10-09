package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

const nativeCycloneDXFixture = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"one","version":"1","purl":"pkg:generic/one@1"}]}`
const nativeSPDXFixture = `{"spdxVersion":"SPDX-2.3","packages":[{"name":"one","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:generic/one@1"}]}]}`
const nativeOpenAPIFixture = `{"openapi":"3.1.0","info":{"title":"API","version":"1","description":"private-source-description"},"paths":{"/items":{"get":{"operationId":"listItems","responses":{"200":{"description":"ok"}}}}}}`

type documentFixtureCase struct{ name, raw, media, parser, job string }

func documentFixtureCases() []documentFixtureCase {
	return []documentFixtureCase{{"cyclonedx", nativeCycloneDXFixture, evidenceapp.CycloneDXMediaType, app.ParserVersionCycloneDXJSON, "parse_sbom"}, {"spdx", nativeSPDXFixture, evidenceapp.SPDXMediaType, app.ParserVersionSPDXJSON, "parse_sbom"}, {"openapi", nativeOpenAPIFixture, evidenceapp.OpenAPIMediaType, app.ParserVersionOpenAPIJSON, "parse_openapi_contract"}}
}

type documentFixtureResult struct {
	id, evidence string
	value        any
}

func (c documentFixtureCase) preflight(ctx context.Context, f ingestionFixtureCommands, a domain.Actor, product, release, artifact string) error {
	if c.name == "openapi" {
		return f.AuthorizeUploadOpenAPIContract(ctx, a, evidenceapp.OpenAPIIngestionInput{ProductID: product, ReleaseID: release, Version: "1"})
	}
	return f.AuthorizeUploadSBOM(ctx, a, evidenceapp.SBOMIngestionInput{ReleaseID: release, ArtifactID: artifact, Format: c.name})
}
func (c documentFixtureCase) upload(ctx context.Context, f ingestionFixtureCommands, a domain.Actor, product, release, artifact string, source evidenceapp.PayloadSource) (documentFixtureResult, error) {
	if c.name == "openapi" {
		v, err := f.UploadOpenAPIContractPayload(ctx, a, evidenceapp.OpenAPIIngestionInput{ProductID: product, ReleaseID: release, Version: "1"}, source)
		return documentFixtureResult{v.ID, v.EvidenceID, v}, err
	}
	v, err := f.UploadSBOMPayload(ctx, a, evidenceapp.SBOMIngestionInput{ReleaseID: release, ArtifactID: artifact, Format: c.name}, source)
	return documentFixtureResult{v.ID, v.EvidenceID, v}, err
}
func (c documentFixtureCase) zero() any {
	if c.name == "openapi" {
		return evidencedomain.OpenAPIContract{}
	}
	return evidencedomain.SBOM{}
}

type documentFixtureReader struct {
	io.ReadCloser
	closes *int
}

func (r documentFixtureReader) Close() error { *r.closes++; return r.ReadCloser.Close() }
func documentFixtureSource(raw []byte) (evidenceapp.PayloadSource, *int, *int) {
	source := evidenceapp.BytesPayloadSource(raw)
	opens, closes := new(int), new(int)
	source.Open = func() (io.ReadCloser, error) {
		*opens++
		return documentFixtureReader{io.NopCloser(bytes.NewReader(raw)), closes}, nil
	}
	return source, opens, closes
}

func TestDocumentIngestionNativeFixtureUsesExplicitResourcesAndAtomicDigestBoundEffects(t *testing.T) {
	for _, tc := range documentFixtureCases() {
		t.Run(tc.name, func(t *testing.T) {
			ledger, base, objects := signatureRegressionLedger(t)
			owner := seedSignatureFixtureScope(t, ledger, "Owner")
			release, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
			if err != nil {
				t.Fatal(err)
			}
			factory := &operatorQueryFailureFactory{base: base}
			rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("document ingestion used aggregate clock") }})
			clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 15, 0, 0, 0, time.UTC)}
			f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}, objects: objects, clock: clock}
			human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceWrite}}}}
			source, opens, closes := documentFixtureSource([]byte(tc.raw))
			before, err := base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.preflight(t.Context(), f, human, owner.product.ID, release.ID, owner.artifact.ID); err != nil {
				t.Fatal("current preflight rejected", err)
			}
			after, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) || clock.calls != 0 || objects.stages != 0 || *opens != 0 {
				t.Fatal("preflight parsed/staged/wrote/time", err)
			}
			result, err := tc.upload(t.Context(), f, human, owner.product.ID, release.ID, owner.artifact.ID, source)
			if err != nil {
				t.Fatal(err)
			}
			if result.id == "" || result.evidence == "" || *opens == 0 || *opens != *closes {
				t.Fatal("missing identities or leaked source stream")
			}
			if tc.name == "openapi" {
				want := evidencedomain.OpenAPIContract{ID: result.id, TenantID: human.TenantID, ProductID: owner.product.ID, ReleaseID: release.ID, Version: "1", Hash: source.Digest, PathCount: 1, Operations: []evidencedomain.OpenAPIOperation{{Path: "/items", Method: "GET", OperationID: "listItems", ResponseStatuses: []string{"200"}}}, EvidenceID: result.evidence, CreatedAt: clock.at}
				if !reflect.DeepEqual(result.value, want) {
					t.Fatal("contract lost full normalized DTO", result.value, want)
				}
				v := result.value.(evidencedomain.OpenAPIContract)
				v.Operations[0].ResponseStatuses[0] = "mutated"
			} else {
				version := "1.6"
				if tc.name == "spdx" {
					version = "SPDX-2.3"
				}
				want := evidencedomain.SBOM{ID: result.id, TenantID: human.TenantID, EvidenceID: result.evidence, ReleaseID: release.ID, ArtifactID: owner.artifact.ID, Format: tc.name, SpecVersion: version, ComponentCount: 1, Components: []evidencedomain.SBOMComponent{{Identity: "purl:pkg:generic/one@1", Name: "one", Version: "1", PURL: "pkg:generic/one@1"}}, CreatedAt: clock.at}
				if !reflect.DeepEqual(result.value, want) {
					t.Fatal("SBOM lost full normalized DTO", result.value, want)
				}
				v := result.value.(evidencedomain.SBOM)
				v.Components[0].Name = "mutated"
			}
			after, err = base.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Evidence) != len(before.Evidence)+1 || len(after.ObjectPayloads) != len(before.ObjectPayloads)+1 || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+2 || len(after.OutboxJobs) != len(before.OutboxJobs)+2 || objects.stages != 1 {
				t.Fatal("document/evidence/payload/audit/jobs not atomic")
			}
			e := after.Evidence[result.evidence]
			provenance, ok := e.Metadata["parser"].(map[string]any)
			if !ok || provenance["version"] != tc.parser || e.TenantID != human.TenantID || e.ReleaseID != release.ID || e.PayloadHash != source.Digest || e.PayloadSize != source.Size || e.PayloadMediaType != tc.media || e.CanonicalHash == "" || e.ChainEntryID == "" {
				t.Fatal("evidence lost digest/provenance/current scope")
			}
			encoded, err := json.Marshal(e)
			if err != nil || strings.Contains(string(encoded), "private-source-description") {
				t.Fatal("raw OpenAPI description leaked into metadata", err)
			}
			if tc.name == "openapi" {
				if after.OpenAPIContracts[result.id].Operations[0].ResponseStatuses[0] != "200" {
					t.Fatal("operation result aliases repository")
				}
			} else {
				if after.SBOMs[result.id].Components[0].Name != "one" {
					t.Fatal("component result aliases repository")
				}
			}
			for _, entry := range after.AuditEntries[human.TenantID][len(before.AuditEntries[human.TenantID]):] {
				if entry.ActorID != human.UserID || entry.ActorType != "human_user" || entry.OccurredAt != clock.at || entry.PayloadHash != source.Digest {
					t.Fatal("document audit lost caller/time/digest")
				}
			}
			for _, p := range after.ObjectPayloads {
				if p.TenantID != human.TenantID || p.Digest != source.Digest {
					continue
				}
				obj, err := objects.Get(t.Context(), p.StagingKey)
				if err != nil || !bytes.Equal(obj.Bytes, []byte(tc.raw)) {
					t.Fatal("staged object bytes changed", err)
				}
				if _, err := objects.Get(t.Context(), p.FinalKey); !errors.Is(err, app.ErrNotFound) {
					t.Fatal("object finalized before job", err)
				}
			}
			foundJob := false
			for _, job := range after.OutboxJobs {
				if job.SubjectID == result.id {
					foundJob = true
					if job.Kind != tc.job || job.Payload["parser_version"] != tc.parser || job.Payload["payload_hash"] != source.Digest || job.Payload["payload_ref"] != e.PayloadRef {
						t.Fatal("parser job identity incomplete")
					}
				}
			}
			if !foundJob {
				t.Fatal("missing parser job")
			}
			// A failed commit leaves only unreferenced staged bytes, not any effect.
			factory.fail = true
			failedRaw := []byte(tc.raw + " ")
			failedSource := evidenceapp.BytesPayloadSource(failedRaw)
			failed, err := tc.upload(t.Context(), f, human, owner.product.ID, release.ID, owner.artifact.ID, failedSource)
			if err == nil || failed.id != "" || !reflect.DeepEqual(failed.value, tc.zero()) {
				t.Fatal("failed document commit exposed result", err)
			}
			last, err := base.Snapshot()
			if err != nil || !reflect.DeepEqual(after, last) || objects.stages != 2 {
				t.Fatal("failed commit published document effects", err)
			}
			staging, final, err := app.CanonicalObjectPayloadKeys(human.TenantID, failedSource.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if obj, err := objects.Get(t.Context(), staging); err != nil || !bytes.Equal(obj.Bytes, failedRaw) {
				t.Fatal("failed commit did not exercise exact staging", err)
			}
			if _, err := objects.Get(t.Context(), final); !errors.Is(err, app.ErrNotFound) {
				t.Fatal("failed commit finalized bytes", err)
			}
		})
	}
}

func TestDocumentIngestionNativeFixtureRejectsForeignAndMalformedSourcesBeforeEffects(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	foreign := seedSignatureFixtureScope(t, ledger, "Foreign")
	release, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	foreignRelease, err := ledger.CreateRelease(t.Context(), foreign.actor, foreign.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 15, 0, 0, 0, time.UTC)}
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, objects: objects, clock: clock}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{app.ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{app.ScopeEvidenceWrite}}}}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range documentFixtureCases() {
		t.Run(tc.name, func(t *testing.T) {
			source, opens, closes := documentFixtureSource([]byte(tc.raw))
			if v, err := tc.upload(t.Context(), f, human, owner.product.ID, foreignRelease.ID, owner.artifact.ID, source); !errors.Is(err, app.ErrNotFound) || v.id != "" || !reflect.DeepEqual(v.value, tc.zero()) || *opens != 0 {
				t.Fatal("foreign release parsed/wrote", err)
			}
			if tc.name != "openapi" {
				if _, err := tc.upload(t.Context(), f, human, owner.product.ID, release.ID, foreign.artifact.ID, source); !errors.Is(err, app.ErrForbidden) || *opens != 0 {
					t.Fatal("foreign artifact parsed/wrote", err)
				}
				if _, err := tc.upload(t.Context(), f, owner.actor, owner.product.ID, release.ID, foreign.artifact.ID, source); !errors.Is(err, app.ErrNotFound) || *opens != 0 {
					t.Fatal("tenant-wide actor accepted foreign artifact", err)
				}
			}
			revoked := human
			revoked.ResourceGrants = nil
			if _, err := tc.upload(t.Context(), f, revoked, owner.product.ID, release.ID, owner.artifact.ID, source); !errors.Is(err, app.ErrForbidden) || *opens != 0 {
				t.Fatal("revoked grant parsed/wrote", err)
			}
			for _, bad := range []evidenceapp.PayloadSource{{Digest: source.Digest, Size: source.Size}, {Digest: source.Digest, Size: app.EvidenceDocumentLimit + 1, Open: source.Open}, {Digest: "sha256:" + strings.Repeat("f", 64), Size: source.Size, Open: source.Open}, {Digest: source.Digest, Size: source.Size + 1, Open: source.Open}, evidenceapp.BytesPayloadSource([]byte(`{}`)), evidenceapp.BytesPayloadSource([]byte(`[]`))} {
				if v, err := tc.upload(t.Context(), f, human, owner.product.ID, release.ID, owner.artifact.ID, bad); !errors.Is(err, app.ErrValidation) || v.id != "" || !reflect.DeepEqual(v.value, tc.zero()) {
					t.Fatal("malformed/digest/size mismatch accepted", err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := tc.upload(ctx, f, human, owner.product.ID, release.ID, owner.artifact.ID, source); !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled ingestion accepted", err)
			}
			if *opens != *closes {
				t.Fatal("invalid source leaked stream")
			}
		})
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || objects.stages != 0 || clock.calls != 0 {
		t.Fatal("rejected ingestion published effects/time/staging", err)
	}
}

func TestDocumentIngestionNativeFixtureKeepsExplicitParserPolicyAndNoStorageSemanticsOnRebind(t *testing.T) {
	for _, tc := range documentFixtureCases() {
		for _, storage := range []bool{false, true} {
			mode := "metadata-only"
			if storage {
				mode = "worker-owned"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				ledger, base, objects := signatureRegressionLedger(t)
				owner := seedSignatureFixtureScope(t, ledger, "Owner")
				release, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
				if err != nil {
					t.Fatal(err)
				}
				clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 15, 0, 0, 0, time.UTC)}
				f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: clock, workerOwnedParsers: true, repositoryScope: true}
				if storage {
					f.objects = objects
				}
				s := &Server{sbomIngestionCommands: f, openAPIIngestionCommands: f}
				rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: base, Now: func() time.Time { panic("rebound document used aggregate clock") }})
				s.bindIngestionFixturePorts(rebound)
				for _, port := range []any{s.sbomIngestionCommands, s.openAPIIngestionCommands} {
					bound, ok := port.(ingestionFixtureCommands)
					if !ok || bound.ledger != rebound || bound.objects != f.objects || bound.clock != clock || !bound.workerOwnedParsers || !bound.repositoryScope {
						t.Fatal("rebind discarded explicit parser/resources")
					}
				}
				f = s.sbomIngestionCommands.(ingestionFixtureCommands)
				before, err := base.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				source := evidenceapp.BytesPayloadSource([]byte(tc.raw))
				result, err := tc.upload(t.Context(), f, owner.actor, owner.product.ID, release.ID, owner.artifact.ID, source)
				if err != nil {
					t.Fatal(err)
				}
				after, err := base.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				if len(after.Evidence) != len(before.Evidence)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+2 {
					t.Fatal("parser acceptance lost evidence/audits")
				}
				e := after.Evidence[result.evidence]
				if storage {
					if e.PayloadRef == "" || objects.stages != 1 || len(after.ObjectPayloads) != len(before.ObjectPayloads)+1 || len(after.OutboxJobs) != len(before.OutboxJobs)+2 {
						t.Fatal("worker-owned source missing managed payload/jobs")
					}
					if tc.name == "openapi" {
						v := result.value.(evidencedomain.OpenAPIContract)
						p := after.OpenAPIContracts[result.id]
						if v.PathCount != 1 || len(v.Operations) != 1 || p.PathCount != 0 || p.Operations != nil {
							t.Fatal("worker-owned contract published unfinished projection")
						}
					} else {
						v := result.value.(evidencedomain.SBOM)
						p := after.SBOMs[result.id]
						if v.ComponentCount != 1 || len(v.Components) != 1 || v.SpecVersion == "" || p.ComponentCount != 0 || p.SpecVersion != "" || p.Components != nil {
							t.Fatal("worker-owned SBOM published unfinished projection")
						}
					}
				} else {
					if e.PayloadRef != "" || objects.stages != 0 || len(after.ObjectPayloads) != len(before.ObjectPayloads) || len(after.OutboxJobs) != len(before.OutboxJobs)+1 {
						t.Fatal("explicit no-storage recovered Ledger storage or lost parser job")
					}
					if tc.name == "openapi" {
						if after.OpenAPIContracts[result.id].Operations == nil || after.OpenAPIContracts[result.id].PathCount != 1 {
							t.Fatal("metadata-only contract falsely deferred parsing")
						}
					} else {
						if len(after.SBOMs[result.id].Components) != 1 {
							t.Fatal("metadata-only SBOM falsely deferred parsing")
						}
					}
				}
				kind, action := "sbom", "parsed"
				if tc.name == "openapi" {
					kind = "openapi_contract"
				}
				if storage {
					action = "accepted"
				}
				actions := []string{"evidence.created", kind + "." + action}
				for i, entry := range after.AuditEntries[owner.actor.TenantID][len(before.AuditEntries[owner.actor.TenantID]):] {
					if entry.EntryType != actions[i] || entry.ActorID != owner.actor.KeyID || entry.ActorType != "api_key" || entry.OccurredAt != clock.at {
						t.Fatal("parser policy audit action/caller/time changed", entry.EntryType)
					}
				}
			})
		}
	}
	explicitSBOM, explicitOpenAPI := &sbomIngestionHTTPFake{}, &openAPIIngestionHTTPFake{}
	s := &Server{sbomIngestionCommands: explicitSBOM, openAPIIngestionCommands: explicitOpenAPI}
	s.bindIngestionFixturePorts(nil)
	s.bindDocumentIngestionFixtureResources(nil, nil, true)
	if s.sbomIngestionCommands != explicitSBOM || s.openAPIIngestionCommands != explicitOpenAPI {
		t.Fatal("rebind replaced injected ingestion ports")
	}
}

func TestDocumentIngestionNativeFixtureRejectsChangedRepeatableBytesAndUntrustedStaging(t *testing.T) {
	ledger, base, objects := signatureRegressionLedger(t)
	owner := seedSignatureFixtureScope(t, ledger, "Owner")
	release, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	clock := &diffFixtureClock{at: time.Date(2026, 10, 9, 15, 0, 0, 0, time.UTC)}
	f := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, objects: objects, clock: clock}
	before, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	tc := documentFixtureCases()[2]
	source := evidenceapp.BytesPayloadSource([]byte(tc.raw))
	opens, closes := 0, 0
	source.Open = func() (io.ReadCloser, error) {
		opens++
		raw := tc.raw
		if opens > 1 {
			raw = strings.Replace(raw, `"version":"1"`, `"version":"2"`, 1)
		}
		return documentFixtureReader{io.NopCloser(strings.NewReader(raw)), &closes}, nil
	}
	if v, err := tc.upload(t.Context(), f, owner.actor, owner.product.ID, release.ID, owner.artifact.ID, source); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v.value, tc.zero()) || opens != 2 || closes != opens || objects.stages != 1 {
		t.Fatal("changed reopened bytes trusted or stream leaked", err, opens, closes)
	}
	f.objects = securityDocumentCorruptFixtureStore{objects}
	if v, err := tc.upload(t.Context(), f, owner.actor, owner.product.ID, release.ID, owner.artifact.ID, evidenceapp.BytesPayloadSource([]byte(tc.raw))); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v.value, tc.zero()) || objects.stages != 2 {
		t.Fatal("untrusted staging metadata accepted", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed staging published evidence/document/audit/jobs", err)
	}
	missing := ingestionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})}, objects: objects, clock: clock}
	if err := tc.preflight(t.Context(), missing, owner.actor, owner.product.ID, release.ID, owner.artifact.ID); !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatal("missing repository preflight fell back to Ledger", err)
	}
	if v, err := tc.upload(t.Context(), missing, owner.actor, owner.product.ID, release.ID, owner.artifact.ID, evidenceapp.BytesPayloadSource([]byte(tc.raw))); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v.value, tc.zero()) {
		t.Fatal("missing repository write fell back to Ledger", err)
	}
}
