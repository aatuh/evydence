package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type sbomIngestionFixtureRunner struct {
	base *fakeEvidenceTransactions
	fail string
}

func (r sbomIngestionFixtureRunner) ExecuteSBOMIngestion(ctx context.Context, fn func(context.Context, SBOMIngestionTransaction) error) error {
	return r.base.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return fn(ctx, sbomIngestionFixtureTx{EvidenceCreationTransaction: failingCreationTransaction{evidenceCreationTransaction{tx}, r.fail}, ingestion: tx.Ingestion()})
	})
}

type sbomIngestionFixtureTx struct {
	EvidenceCreationTransaction
	ingestion IngestionRepository
}

func (t sbomIngestionFixtureTx) InsertSBOM(ctx context.Context, v evidencedomain.SBOM) error {
	return t.ingestion.InsertSBOM(ctx, v)
}
func newSBOMIngestionFixture(t *testing.T, format string) (*SBOMIngestionCommands, *evidenceServiceFixture, SBOMIngestionInput) {
	t.Helper()
	f := newEvidenceServiceFixture(t)
	f.reader.artifacts["artifact"] = f.actor.TenantID
	f.transactions.state.artifactTenants["artifact"] = f.actor.TenantID
	f.parser.sbom = ParsedSBOM{Format: format, SpecVersion: map[string]string{"cyclonedx": "1.6", "spdx": "SPDX-2.3"}[format], ParserVersion: "parser.v1", Components: []evidencedomain.SBOMComponent{{Identity: "name:api@1", Name: "api", Version: "1"}}, Metadata: map[string]any{"component_count": 1}, Limitations: []string{"raw-only fields retained"}}
	c, err := NewSBOMIngestionCommands(SBOMIngestionCommandConfig{Authorizer: f.authorizer, Transactions: sbomIngestionFixtureRunner{base: f.transactions}, Parser: f.parser, Objects: f.objects, Payloads: f.objects, Canonicalizer: f.canonicalizer, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: f.service.clock, IDs: f.service.ids, WorkerOwnedParsers: true})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, SBOMIngestionInput{ReleaseID: " rel_1 ", ArtifactID: " artifact ", Format: format}
}
func TestSBOMIngestionCommandsPreserveBothFormatsAndProjectionOwnership(t *testing.T) {
	for _, format := range []string{"cyclonedx", "spdx"} {
		for _, mode := range []string{"worker", "inline", "without-object"} {
			t.Run(format+"/"+mode, func(t *testing.T) {
				c, f, in := newSBOMIngestionFixture(t, format)
				f.actor.KeyID, f.actor.UserID = "", "human"
				c.config.WorkerOwnedParsers = mode != "inline"
				f.objects.noObject = mode == "without-object"
				if err := c.AuthorizeUploadSBOM(t.Context(), f.actor, in); err != nil || f.parser.sbomCalls != 0 || f.objects.sourceStageCalls != 0 {
					t.Fatal("replay parsed/staged", err)
				}
				source := testPayloadSource(`{}`)
				v, err := c.UploadSBOMPayload(t.Context(), f.actor, in, source)
				if err != nil || v.ID == "" || v.ReleaseID != "rel_1" || v.ArtifactID != "artifact" || v.Format != format || v.SpecVersion != f.parser.sbom.SpecVersion || v.ComponentCount != 1 || len(v.Components) != 1 || v.CreatedAt != f.now {
					t.Fatal(v, err)
				}
				s := f.transactions.state
				jobs, payloads := 2, 1
				if mode == "without-object" {
					jobs, payloads = 1, 0
				}
				if len(s.evidence) != 1 || len(s.sboms) != 1 || len(s.audit) != 2 || len(s.outbox) != jobs || len(s.payloads) != payloads {
					t.Fatal("partial ingestion effects", s)
				}
				p := s.sboms[v.ID]
				if mode == "worker" && (p.ComponentCount != 0 || p.Components != nil) || mode != "worker" && (p.ComponentCount != 1 || len(p.Components) != 1) {
					t.Fatal("projection ownership changed", p)
				}
				e := s.evidence[v.EvidenceID]
				if e.Type != "sbom" || e.Subtype != format || e.PayloadHash != source.Digest || e.CanonicalHash != testDigest('c') || e.ChainEntryID == "" || len(e.SubjectRefs) != 2 || e.SubjectRefs[0].ID != "artifact" || e.SubjectRefs[1].ID != "rel_1" || e.Metadata["component_count"] != 1 {
					t.Fatal("evidence semantics changed", e)
				}
				for _, a := range s.audit {
					if a.ActorID != "human" || a.ActorType != "human_user" || a.PayloadHash != source.Digest {
						t.Fatal("audit identity", a)
					}
				}
				j := s.outbox[len(s.outbox)-1]
				if j.Kind != "parse_sbom" || j.SubjectID != v.ID || j.Payload["parser_version"] != "parser.v1" || j.Payload["payload_hash"] != source.Digest {
					t.Fatal(j)
				}
				v.Components[0].Name = "changed"
				if f.parser.sbom.Components[0].Name != "api" {
					t.Fatal("component aliases parser")
				}
			})
		}
	}
}
func TestSBOMIngestionCommandsRejectBeforeParsingAndRollbackWrites(t *testing.T) {
	for _, point := range []string{"scope", "artifact", "authorization", "parser", "stager", "payload", "outbox", "audit", "second-audit", "insert", "sbom", "commit"} {
		t.Run(point, func(t *testing.T) {
			c, f, in := newSBOMIngestionFixture(t, "cyclonedx")
			c.config.Transactions = sbomIngestionFixtureRunner{f.transactions, point}
			switch point {
			case "authorization":
				f.authorizer.authorize = func(r application.AuthorizationRequest) error {
					if r.Resources.ArtifactID != "" {
						return application.ErrForbidden
					}
					return nil
				}
			case "parser":
				f.parser.err = ErrConflict
			case "stager":
				f.objects.stageErr = ErrConflict
			case "second-audit":
				f.transactions.auditFailAt = 2
			case "sbom":
				f.transactions.ingestionWriteErr = ErrConflict
			case "commit":
				f.transactions.commitErr = ErrConflict
			}
			v, err := c.UploadSBOMPayload(t.Context(), f.actor, in, testPayloadSource(`{}`))
			s := f.transactions.state
			if err == nil || v.ID != "" || len(s.evidence)+len(s.sboms)+len(s.audit)+len(s.outbox)+len(s.payloads) != 0 {
				t.Fatal("failure leaked effects", v, err, s)
			}
			if (point == "scope" || point == "artifact" || point == "authorization") && (f.parser.sbomCalls != 0 || f.objects.sourceStageCalls != 0) {
				t.Fatal("denied input reached parser/stager")
			}
		})
	}
	for _, bad := range []SBOMIngestionInput{{}, {ReleaseID: "rel_1", Format: "unknown"}, {ReleaseID: "rel_1\x00", Format: "spdx"}, {ReleaseID: strings.Repeat("x", 1025), Format: "spdx"}, {ReleaseID: "rel_1", ArtifactID: "bad\x00", Format: "spdx"}} {
		c, f, _ := newSBOMIngestionFixture(t, "spdx")
		if _, err := c.UploadSBOMPayload(t.Context(), f.actor, bad, testPayloadSource(`{}`)); !errors.Is(err, ErrValidation) || f.parser.sbomCalls != 0 {
			t.Fatal("bad metadata processed", err)
		}
	}
}
func TestSBOMIngestionCommandsRejectInvalidParsedProjection(t *testing.T) {
	for _, mutate := range []func(*ParsedSBOM){
		func(p *ParsedSBOM) { p.Format = "spdx" }, func(p *ParsedSBOM) { p.SpecVersion = "" }, func(p *ParsedSBOM) { p.ParserVersion = "bad\x00" }, func(p *ParsedSBOM) { p.Components[0].Name = "bad\x00" }, func(p *ParsedSBOM) { p.Components = make([]evidencedomain.SBOMComponent, SBOMDiffComponentLimit+1) }, func(p *ParsedSBOM) { m := map[string]any{}; m["cycle"] = m; p.Metadata = m }, func(p *ParsedSBOM) { p.Limitations = []string{"bad\x00"} },
	} {
		c, f, in := newSBOMIngestionFixture(t, "cyclonedx")
		mutate(&f.parser.sbom)
		if v, err := c.UploadSBOMPayload(t.Context(), f.actor, in, testPayloadSource(`{}`)); !errors.Is(err, ErrValidation) || v.ID != "" || f.objects.sourceStageCalls != 0 {
			t.Fatal("invalid parser output staged", v, err)
		}
	}
	if _, err := NewSBOMIngestionCommands(SBOMIngestionCommandConfig{}); err == nil {
		t.Fatal("missing ports accepted")
	}
}

func TestSBOMIngestionCommandsRejectInvalidSourceAndCancelledContextBeforeEffects(t *testing.T) {
	for _, kind := range []string{"zero-size", "negative-size", "oversize", "digest", "padded-digest", "missing-open", "nil-context", "cancelled", "tenant", "actor", "scope"} {
		t.Run(kind, func(t *testing.T) {
			c, f, in := newSBOMIngestionFixture(t, "spdx")
			source := testPayloadSource(`{}`)
			ctx := t.Context()
			want := ErrValidation
			switch kind {
			case "zero-size":
				source.Size = 0
			case "negative-size":
				source.Size = -1
			case "oversize":
				source.Size = EvidenceDocumentLimit + 1
			case "digest":
				source.Digest = "invalid"
			case "padded-digest":
				source.Digest = " " + source.Digest
			case "missing-open":
				source.Open = nil
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "tenant":
				f.actor.TenantID = "bad\x00"
			case "actor":
				f.actor.KeyID, f.actor.UserID = "", ""
			case "scope":
				f.authorizer.err = application.ErrForbidden
				want = application.ErrForbidden
			}
			v, err := c.UploadSBOMPayload(ctx, f.actor, in, source)
			s := f.transactions.state
			if !errors.Is(err, want) || v.ID != "" || f.parser.sbomCalls != 0 || f.objects.sourceStageCalls != 0 || len(s.evidence)+len(s.sboms)+len(s.audit)+len(s.outbox)+len(s.payloads) != 0 {
				t.Fatal("invalid input produced effects", v, err, s)
			}
		})
	}
}
