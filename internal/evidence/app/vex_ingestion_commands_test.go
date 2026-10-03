package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type vexIngestionFixtureRunner struct {
	base *fakeEvidenceTransactions
	fail string
}

func (r vexIngestionFixtureRunner) ExecuteVEXIngestion(ctx context.Context, fn func(context.Context, VEXIngestionTransaction) error) error {
	return r.base.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return fn(ctx, vexIngestionFixtureTx{EvidenceCreationTransaction: failingCreationTransaction{evidenceCreationTransaction{tx}, r.fail}, ingestion: tx.Ingestion(), fail: r.fail})
	})
}

type vexIngestionFixtureTx struct {
	EvidenceCreationTransaction
	ingestion IngestionRepository
	fail      string
}

func (t vexIngestionFixtureTx) InsertVEXDocument(ctx context.Context, v evidencedomain.VEXDocument) error {
	if t.fail == "document" {
		return ErrConflict
	}
	return t.ingestion.InsertVEXDocument(ctx, v)
}
func (t vexIngestionFixtureTx) InsertVEXImportReport(ctx context.Context, v evidencedomain.VEXImportReport) error {
	if t.fail == "report" {
		return ErrConflict
	}
	return t.ingestion.InsertVEXImportReport(ctx, v)
}

func newVEXIngestionFixture(t *testing.T, format string) (*VEXIngestionCommands, *evidenceServiceFixture) {
	t.Helper()
	f := newEvidenceServiceFixture(t)
	f.transactions.state.artifactTenants["art_1"] = f.actor.TenantID
	f.parser.vex = ParsedVEX{Format: format, Author: "security@example.test", Version: "1", ParserVersion: OpenVEXParserVersion, StatementCount: 1, ValidStatementCount: 1, StatusSummary: map[string]int{"fixed": 1}, Statements: []VEXDecisionStatement{{StatementIndex: 1, Vulnerability: "CVE-2026-1", Products: []string{"pkg:generic/api@1"}, Status: "fixed", Justification: "fixed_in_release", ImpactStatement: "Fixed before release.", ActionStatement: "Upgrade to this release."}}, Metadata: map[string]any{"format": format}, Warnings: []string{"parser warning"}, Limitations: []string{"source evidence only"}}
	if format == "cyclonedx" {
		f.parser.vex.Version, f.parser.vex.ParserVersion = "1.6", CycloneDXVEXParserVersion
		f.parser.vex.StatementCount = 2
		f.parser.vex.InvalidStatements = []evidencedomain.VEXImportIssue{{StatementIndex: 2, Code: "missing_vulnerability", Detail: "missing id"}}
	}
	c, err := NewVEXIngestionCommands(VEXIngestionCommandConfig{Authorizer: f.authorizer, Transactions: vexIngestionFixtureRunner{base: f.transactions}, Parser: f.parser, Objects: f.objects, Payloads: f.objects, Canonicalizer: f.canonicalizer, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: f.service.clock, IDs: f.service.ids})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestVEXIngestionCommandsPreserveAcceptedReportsAndPostCommitDecisionRequests(t *testing.T) {
	for _, format := range []string{"openvex", "cyclonedx"} {
		for _, noObject := range []bool{false, true} {
			t.Run(format+map[bool]string{false: "/staged", true: "/without-object"}[noObject], func(t *testing.T) {
				c, f := newVEXIngestionFixture(t, format)
				f.objects.noObject = noObject
				f.actor.KeyID, f.actor.UserID = "", "human"
				in := VEXIngestionInput{ReleaseID: " rel_1 ", ArtifactID: " art_1 ", Format: format}
				if err := c.AuthorizeUploadVEX(t.Context(), f.actor, in); err != nil || f.parser.vexCalls+f.objects.sourceStageCalls != 0 {
					t.Fatal("replay guard parsed or staged", err)
				}
				source := testPayloadSource(`{}`)
				v, err := c.UploadVEXPayload(t.Context(), f.actor, in, source)
				s := f.transactions.state
				jobs, payloads := 2, 1
				if noObject {
					jobs, payloads = 1, 0
				}
				if err != nil || v.ID == "" || v.EvidenceID == "" || v.ReleaseID != "rel_1" || v.ArtifactID != "art_1" || v.Format != format || v.StatementCount != f.parser.vex.StatementCount || v.StatusSummary["fixed"] != 1 || v.CreatedAt != f.now || len(s.evidence) != 1 || len(s.vexDocuments) != 1 || len(s.vexImportReports) != 1 || len(s.audit) != 2 || len(s.outbox) != jobs || len(s.payloads) != payloads {
					t.Fatal("partial or changed VEX result", v, err, s)
				}
				var report evidencedomain.VEXImportReport
				for _, r := range s.vexImportReports {
					report = r
				}
				if report.Status != "accepted" || report.VEXDocumentID != v.ID || report.EvidenceID != v.EvidenceID || report.ParserVersion != f.parser.vex.ParserVersion || report.DecisionsCreated+report.DecisionsSuperseded != 0 || len(report.InvalidStatements) != len(f.parser.vex.InvalidStatements) || !stringSliceContains(report.Warnings, VEXAsyncDecisionWarning) || !stringSliceContains(report.Warnings, "parser warning") || report.CreatedAt != f.now || report.UpdatedAt != f.now {
					t.Fatal("report changed", report)
				}
				job := s.outbox[len(s.outbox)-1]
				if job.Kind != "parse_vex" || job.SubjectID != v.ID || job.Payload["worker_create_decisions"] != true || job.Payload["decision_request_schema"] != VEXDecisionRequestSchemaVersion || job.Payload["actor_type"] != "human_user" || job.Payload["actor_id"] != "human" || job.Payload["evidence_id"] != v.EvidenceID || job.Payload["release_id"] != v.ReleaseID || job.Payload["artifact_id"] != v.ArtifactID || job.Payload["import_report_id"] != report.ID || job.Payload["parser_version"] != f.parser.vex.ParserVersion || job.Payload["payload_hash"] != source.Digest {
					t.Fatal("decision request changed", job)
				}
				requireNormalizedVEXStatement(t, job.Payload, 0, 1, "CVE-2026-1", []string{"pkg:generic/api@1"}, "fixed")
				for _, event := range s.audit {
					if event.ActorType != "human_user" || event.ActorID != "human" || event.PayloadHash != source.Digest {
						t.Fatal("audit identity changed", event)
					}
				}
				e := s.evidence[v.EvidenceID]
				if e.Type != "vex" || e.Subtype != format || e.CanonicalHash != testDigest('c') || e.ChainEntryID == "" || e.PayloadHash != source.Digest || e.VerificationStatus != "pending" || len(e.SubjectRefs) != 2 {
					t.Fatal("evidence binding changed", e)
				}
				v.StatusSummary["fixed"] = 99
				f.parser.vex.Statements[0].Products[0] = "changed"
				if s.vexDocuments[v.ID].StatusSummary["fixed"] != 1 || job.Payload["decision_statements"].([]map[string]any)[0]["products"].([]string)[0] != "pkg:generic/api@1" {
					t.Fatal("result or parser aliases persisted records")
				}
			})
		}
	}
}

func TestVEXIngestionCommandsAuthorizeBeforeParsingAndRollbackEveryWrite(t *testing.T) {
	for _, point := range []string{"scope", "artifact", "authorization", "parser", "stager", "payload", "outbox", "audit", "second-audit", "insert", "document", "report", "commit"} {
		t.Run(point, func(t *testing.T) {
			c, f := newVEXIngestionFixture(t, "openvex")
			c.config.Transactions = vexIngestionFixtureRunner{f.transactions, point}
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
			case "commit":
				f.transactions.commitErr = ErrConflict
			}
			v, err := c.UploadVEXPayload(t.Context(), f.actor, VEXIngestionInput{ReleaseID: "rel_1", ArtifactID: "art_1", Format: "openvex"}, testPayloadSource(`{}`))
			s := f.transactions.state
			if err == nil || v.ID != "" || len(s.evidence)+len(s.vexDocuments)+len(s.vexImportReports)+len(s.payloads)+len(s.outbox)+len(s.audit) != 0 {
				t.Fatal("failed VEX command published partial effects", v, err, s)
			}
			if (point == "scope" || point == "artifact" || point == "authorization") && f.parser.vexCalls+f.objects.sourceStageCalls != 0 {
				t.Fatal("denial reached parser/stager")
			}
		})
	}
}

func TestVEXIngestionCommandsEnforceExactNormalizedDecisionTextBudget(t *testing.T) {
	for _, extra := range []int{0, 1} {
		c, f := newVEXIngestionFixture(t, "openvex")
		row := f.parser.vex.Statements[0]
		const count = 20
		otherBytes := len(row.Vulnerability) + len(row.Status) + len(row.Justification) + len(row.ActionStatement)
		for _, product := range row.Products {
			otherBytes += len(product)
		}
		row.ImpactStatement = strings.Repeat("x", VEXIngestionStringByteLimit)
		p := &f.parser.vex
		p.Statements = make([]VEXDecisionStatement, count)
		for i := range p.Statements {
			p.Statements[i] = row
			p.Statements[i].StatementIndex = i + 1
		}
		p.Statements[count-1].ImpactStatement = strings.Repeat("x", VEXIngestionStringByteLimit-count*otherBytes+extra)
		p.StatementCount, p.ValidStatementCount, p.StatusSummary["fixed"] = count, count, count
		v, err := c.UploadVEXPayload(t.Context(), f.actor, VEXIngestionInput{ReleaseID: "rel_1", Format: "openvex"}, testPayloadSource(`{}`))
		if extra == 0 {
			if err != nil || v.StatementCount != count || f.objects.sourceStageCalls != 1 {
				t.Fatal("exact worker text budget rejected", v, err)
			}
		} else if !errors.Is(err, ErrValidation) || v.ID != "" || f.objects.sourceStageCalls != 0 || len(f.transactions.state.vexDocuments) != 0 {
			t.Fatal("expanded decision text exceeded worker budget", v, err)
		}
	}
}

func TestVEXIngestionCommandsRejectInvalidInputBeforeParsing(t *testing.T) {
	for _, kind := range []string{"nil-context", "cancelled", "tenant", "actor", "release", "artifact", "format", "digest", "digest-whitespace", "size", "missing-reader", "denied-scope"} {
		t.Run(kind, func(t *testing.T) {
			c, f := newVEXIngestionFixture(t, "openvex")
			ctx, source := t.Context(), testPayloadSource(`{}`)
			in := VEXIngestionInput{ReleaseID: "rel_1", ArtifactID: "art_1", Format: "openvex"}
			want := ErrValidation
			switch kind {
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "tenant":
				f.actor.TenantID = ""
			case "actor":
				f.actor.KeyID, f.actor.UserID = "", ""
			case "release":
				in.ReleaseID = "bad\x00"
			case "artifact":
				in.ArtifactID = strings.Repeat("x", 1025)
			case "format":
				in.Format = "unsupported"
			case "digest":
				source.Digest = "invalid"
			case "digest-whitespace":
				source.Digest += " "
			case "size":
				source.Size = EvidenceDocumentLimit + 1
			case "missing-reader":
				source.Open = nil
			case "denied-scope":
				f.authorizer.authorize = func(application.AuthorizationRequest) error { return application.ErrForbidden }
				want = application.ErrForbidden
			}
			v, err := c.UploadVEXPayload(ctx, f.actor, in, source)
			if !errors.Is(err, want) || v.ID != "" || f.parser.vexCalls+f.objects.sourceStageCalls != 0 || len(f.transactions.state.vexDocuments)+len(f.transactions.state.evidence) != 0 {
				t.Fatal("invalid VEX input reached parser or effects", v, err)
			}
		})
	}
}

func TestVEXIngestionCommandsRejectInvalidProjectionBeforeStaging(t *testing.T) {
	for _, kind := range []string{"format", "parser-version", "summary", "index", "nul", "utf8", "single-string", "statement-count", "product-count", "decision-budget", "warning", "cyclic-metadata"} {
		t.Run(kind, func(t *testing.T) {
			c, f := newVEXIngestionFixture(t, "openvex")
			p := &f.parser.vex
			switch kind {
			case "format":
				p.Format = "cyclonedx"
			case "parser-version":
				p.ParserVersion = "unsupported"
			case "summary":
				p.StatusSummary["fixed"] = 2
			case "index":
				p.Statements[0].StatementIndex = 0
			case "nul":
				p.Statements[0].Vulnerability = "bad\x00"
			case "utf8":
				p.Author = string([]byte{0xff})
			case "single-string":
				p.Statements[0].ImpactStatement = strings.Repeat("x", (1<<20)+1)
			case "statement-count":
				p.StatementCount = 100001
			case "product-count":
				p.Statements[0].Products = make([]string, 100001)
			case "decision-budget":
				row := p.Statements[0]
				row.ImpactStatement = strings.Repeat("x", 1<<20)
				p.Statements = make([]VEXDecisionStatement, 21)
				for i := range p.Statements {
					p.Statements[i] = row
					p.Statements[i].StatementIndex = i + 1
				}
				p.StatementCount, p.ValidStatementCount = 21, 21
				p.StatusSummary["fixed"] = 21
			case "warning":
				p.Warnings = []string{"bad\x00"}
			case "cyclic-metadata":
				p.Metadata["cycle"] = p.Metadata
			}
			if v, err := c.UploadVEXPayload(t.Context(), f.actor, VEXIngestionInput{ReleaseID: "rel_1", Format: "openvex"}, testPayloadSource(`{}`)); !errors.Is(err, ErrValidation) || v.ID != "" || f.objects.sourceStageCalls != 0 {
				t.Fatal("invalid VEX projection staged", v, err)
			}
		})
	}
	if _, err := NewVEXIngestionCommands(VEXIngestionCommandConfig{}); err == nil {
		t.Fatal("missing ports accepted")
	}
}
