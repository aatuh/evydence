package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type openAPIIngestionFixtureRunner struct {
	base *fakeEvidenceTransactions
	fail string
}

func TestOpenAPIIngestionRejectsInvalidParserOutputAndGeneratedState(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mutate      func(*OpenAPIIngestionCommands, *evidenceServiceFixture)
		beforeStage bool
	}{
		{"cyclic metadata", func(_ *OpenAPIIngestionCommands, f *evidenceServiceFixture) {
			m := map[string]any{}
			m["cycle"] = m
			f.parser.contract.Metadata = m
		}, true},
		{"unsupported metadata", func(_ *OpenAPIIngestionCommands, f *evidenceServiceFixture) {
			f.parser.contract.Metadata = map[string]any{"unsupported": func() {}}
		}, true},
		{"invalid parser version", func(_ *OpenAPIIngestionCommands, f *evidenceServiceFixture) {
			f.parser.contract.ParserVersion = "bad\x00"
		}, true},
		{"missing source schema", func(_ *OpenAPIIngestionCommands, f *evidenceServiceFixture) { f.parser.contract.SourceSchema = " " }, true},
		{"invalid operation path", func(_ *OpenAPIIngestionCommands, f *evidenceServiceFixture) {
			f.parser.contract.Operations[0].Path = "/\x00"
		}, true},
		{"invalid response projection", func(_ *OpenAPIIngestionCommands, f *evidenceServiceFixture) {
			f.parser.contract.Operations[0].ResponseStatuses[0] = "200\x00"
		}, true},
		{"invalid limitation", func(_ *OpenAPIIngestionCommands, f *evidenceServiceFixture) {
			f.parser.contract.Limitations = []string{"bad\x00"}
		}, true},
		{"invalid clock", func(c *OpenAPIIngestionCommands, _ *evidenceServiceFixture) {
			c.config.Clock = application.ClockFunc(func() time.Time { return time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) })
		}, false},
		{"invalid contract identity", func(c *OpenAPIIngestionCommands, _ *evidenceServiceFixture) {
			ids := c.config.IDs
			c.config.IDs = application.IDGeneratorFunc(func(prefix string) string {
				if prefix == "oas" {
					return ""
				}
				return ids.NewID(prefix)
			})
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f, in := newOpenAPIIngestionFixture(t)
			tc.mutate(c, f)
			v, err := c.UploadOpenAPIContractPayload(t.Context(), f.actor, in, testPayloadSource(`{}`))
			s := f.transactions.state
			if !errors.Is(err, ErrValidation) || v.ID != "" || len(s.evidence)+len(s.contracts)+len(s.audit)+len(s.outbox)+len(s.payloads) != 0 {
				t.Fatal("invalid parser/generated state persisted", v, err, s)
			}
			if tc.beforeStage && f.objects.sourceStageCalls != 0 {
				t.Fatal("invalid parser output staged")
			}
		})
	}
	c, f, in := newOpenAPIIngestionFixture(t)
	f.transactions.auditFailAt = 2
	if v, err := c.UploadOpenAPIContractPayload(t.Context(), f.actor, in, testPayloadSource(`{}`)); err == nil || v.ID != "" || len(f.transactions.state.evidence)+len(f.transactions.state.contracts)+len(f.transactions.state.audit)+len(f.transactions.state.outbox)+len(f.transactions.state.payloads) != 0 {
		t.Fatal("second audit failure leaked effects", v, err)
	}
}

func (r openAPIIngestionFixtureRunner) ExecuteOpenAPIIngestion(ctx context.Context, fn func(context.Context, OpenAPIIngestionTransaction) error) error {
	return r.base.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return fn(ctx, openAPIIngestionFixtureTx{EvidenceCreationTransaction: failingCreationTransaction{evidenceCreationTransaction{tx}, r.fail}, ingestion: tx.Ingestion()})
	})
}

type openAPIIngestionFixtureTx struct {
	EvidenceCreationTransaction
	ingestion IngestionRepository
}

func (t openAPIIngestionFixtureTx) InsertOpenAPIContract(ctx context.Context, v evidencedomain.OpenAPIContract) error {
	return t.ingestion.InsertOpenAPIContract(ctx, v)
}
func newOpenAPIIngestionFixture(t *testing.T) (*OpenAPIIngestionCommands, *evidenceServiceFixture, OpenAPIIngestionInput) {
	t.Helper()
	f := newEvidenceServiceFixture(t)
	f.parser.contract = ParsedOpenAPIContract{ParserVersion: "openapi-json.v1", SourceSchema: "openapi-3.1.0", PathCount: 1, Operations: []evidencedomain.OpenAPIOperation{{Path: "/health", Method: "GET", ResponseStatuses: []string{"200"}}}, Metadata: map[string]any{"path_count": 1}}
	c, err := NewOpenAPIIngestionCommands(OpenAPIIngestionCommandConfig{Authorizer: f.authorizer, Transactions: openAPIIngestionFixtureRunner{base: f.transactions}, Parser: f.parser, Objects: f.objects, Payloads: f.objects, Canonicalizer: f.canonicalizer, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: f.service.clock, IDs: f.service.ids, WorkerOwnedParsers: true})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, OpenAPIIngestionInput{ProductID: " prod_1 ", ReleaseID: "rel_1", Version: " v1 "}
}
func TestOpenAPIIngestionCommandsBindEvidenceContractAndJobs(t *testing.T) {
	for _, object := range []bool{true, false} {
		t.Run(map[bool]string{true: "worker-owned", false: "without-object"}[object], func(t *testing.T) {
			c, f, in := newOpenAPIIngestionFixture(t)
			f.objects.noObject = !object
			f.actor.KeyID = ""
			f.actor.UserID = "human"
			if err := c.AuthorizeUploadOpenAPIContract(t.Context(), f.actor, in); err != nil || f.parser.contractCalls != 0 || f.objects.sourceStageCalls != 0 {
				t.Fatal("replay inspected payload", err)
			}
			source := testPayloadSource(`{"openapi":"3.1.0"}`)
			v, err := c.UploadOpenAPIContractPayload(t.Context(), f.actor, in, source)
			if err != nil || v.ID == "" || v.ProductID != "prod_1" || v.ReleaseID != "rel_1" || v.Version != "v1" || v.Hash != source.Digest || v.PathCount != 1 || len(v.Operations) != 1 || v.CreatedAt != f.now {
				t.Fatal(v, err)
			}
			s := f.transactions.state
			p := s.contracts[v.ID]
			if len(s.evidence) != 1 || len(s.contracts) != 1 || len(s.audit) != 2 || len(s.outbox) != map[bool]int{true: 2, false: 1}[object] || len(s.payloads) != map[bool]int{true: 1, false: 0}[object] {
				t.Fatal("partial effects", s)
			}
			if object && (p.PathCount != 0 || p.Operations != nil) || !object && (p.PathCount != 1 || len(p.Operations) != 1) {
				t.Fatal("projection ownership changed", p)
			}
			e := s.evidence[v.EvidenceID]
			if e.Type != "openapi_contract" || e.Subtype != "openapi" || e.Title != "OpenAPI contract" || e.PayloadHash != source.Digest || e.PayloadSize != source.Size || e.CanonicalHash != testDigest('c') || e.ChainEntryID == "" || e.Metadata["path_count"] != 1 {
				t.Fatal("evidence contract changed", e)
			}
			for _, a := range s.audit {
				if a.ActorID != "human" || a.ActorType != "human_user" || a.PayloadHash != source.Digest {
					t.Fatal("audit identity changed", a)
				}
			}
			job := s.outbox[len(s.outbox)-1]
			if job.Kind != "parse_openapi_contract" || job.SubjectID != v.ID || job.Payload["payload_hash"] != source.Digest || job.Payload["parser_version"] != "openapi-json.v1" {
				t.Fatal(job)
			}
			v.Operations[0].ResponseStatuses[0] = "mutated"
			if f.parser.contract.Operations[0].ResponseStatuses[0] != "200" {
				t.Fatal("response aliases parser projection")
			}
		})
	}
}
func TestOpenAPIIngestionCommandsRejectBeforeParserAndRollbackFailures(t *testing.T) {
	for _, point := range []string{"scope", "authorization", "parser", "stager", "payload", "outbox", "audit", "insert", "contract", "commit"} {
		t.Run(point, func(t *testing.T) {
			c, f, in := newOpenAPIIngestionFixture(t)
			c.config.Transactions = openAPIIngestionFixtureRunner{f.transactions, point}
			switch point {
			case "authorization":
				f.authorizer.authorize = func(r application.AuthorizationRequest) error {
					if !r.ScopeOnly {
						return application.ErrForbidden
					}
					return nil
				}
			case "parser":
				f.parser.err = ErrConflict
			case "stager":
				f.objects.stageErr = ErrConflict
			case "contract":
				f.transactions.ingestionWriteErr = ErrConflict
			case "commit":
				f.transactions.commitErr = ErrConflict
			}
			v, err := c.UploadOpenAPIContractPayload(t.Context(), f.actor, in, testPayloadSource(`{}`))
			s := f.transactions.state
			if err == nil || v.ID != "" || len(s.evidence)+len(s.contracts)+len(s.audit)+len(s.outbox)+len(s.payloads) != 0 {
				t.Fatal("failure leaked effects", v, err, s)
			}
			if (point == "scope" || point == "authorization") && (f.parser.contractCalls != 0 || f.objects.sourceStageCalls != 0) {
				t.Fatal("denied source parsed/staged")
			}
		})
	}
	for _, bad := range []OpenAPIIngestionInput{{}, {ProductID: "prod_1", Version: " "}, {ProductID: "prod_1\x00", Version: "v1"}, {ProductID: strings.Repeat("x", 1025), Version: "v1"}, {ProductID: "prod_1", Version: strings.Repeat("x", 65537)}} {
		c, f, _ := newOpenAPIIngestionFixture(t)
		if _, err := c.UploadOpenAPIContractPayload(t.Context(), f.actor, bad, testPayloadSource(`{}`)); !errors.Is(err, ErrValidation) || f.parser.contractCalls != 0 {
			t.Fatal("invalid metadata processed", err)
		}
	}
	for _, bad := range []PayloadSource{{}, {Digest: testDigest('a'), Size: EvidenceDocumentLimit + 1, Open: testPayloadSource(`{}`).Open}, {Digest: " " + testDigest('a'), Size: 2, Open: testPayloadSource(`{}`).Open}} {
		c, f, in := newOpenAPIIngestionFixture(t)
		if _, err := c.UploadOpenAPIContractPayload(t.Context(), f.actor, in, bad); !errors.Is(err, ErrValidation) || f.parser.contractCalls != 0 {
			t.Fatal("invalid source processed", err)
		}
	}
	c, f, in := newOpenAPIIngestionFixture(t)
	f.parser.contract.PathCount = -1
	if _, err := c.UploadOpenAPIContractPayload(t.Context(), f.actor, in, testPayloadSource(`{}`)); !errors.Is(err, ErrValidation) || f.objects.sourceStageCalls != 0 {
		t.Fatal("invalid projection staged", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.UploadOpenAPIContractPayload(ctx, f.actor, in, testPayloadSource(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := NewOpenAPIIngestionCommands(OpenAPIIngestionCommandConfig{}); err == nil {
		t.Fatal("missing ports accepted")
	}
}
