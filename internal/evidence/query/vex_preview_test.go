package query

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type vexPreviewArtifactAuth struct {
	calls int
	err   error
}

func (a *vexPreviewArtifactAuth) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	a.calls++
	if r.Scope != "evidence:read" || r.Resources.ArtifactID != "artifact" {
		return ErrConflict
	}
	return a.err
}

type vexPreviewReaderFake struct {
	calls    int
	skip     bool
	err      error
	snapshot VEXPreviewSnapshot
	artifact *vexPreviewArtifactAuth
}

func (r *vexPreviewReaderFake) ReadVEXPreviewSnapshot(_ context.Context, tenant, release, artifact string, prepare VEXPreviewPreparation) (VEXPreviewSnapshot, error) {
	r.calls++
	if r.err != nil {
		return VEXPreviewSnapshot{}, r.err
	}
	if !r.skip {
		ids, err := prepare(application.ResourceReferences{ProductID: "product", ReleaseID: release}, r.artifact)
		if err != nil {
			return VEXPreviewSnapshot{}, err
		}
		if len(ids) != 1 || ids[0] != "CVE-TEST" {
			return VEXPreviewSnapshot{}, ErrConflict
		}
	}
	return r.snapshot, nil
}

type vexPreviewParserFake struct {
	calls  int
	parsed evidenceapp.ParsedVEX
	err    error
}

func (p *vexPreviewParserFake) ParseVEX(_ context.Context, _ string, _ evidenceapp.PayloadSource) (evidenceapp.ParsedVEX, error) {
	p.calls++
	return p.parsed, p.err
}

func TestVEXPreviewsAuthorizeBeforeParsingAndRejectInvalidSnapshots(t *testing.T) {
	for _, kind := range []string{"allowed", "scope", "grant", "artifact", "foreign", "missing-guard", "overflow", "budget", "invalid-finding", "invalid-parser", "parser-error", "reader", "cancelled", "input"} {
		t.Run(kind, func(t *testing.T) {
			at := time.Date(2026, 10, 3, 12, 0, 0, 123456789, time.UTC)
			actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"evidence:read"}}}}
			p := &vexPreviewParserFake{parsed: evidenceapp.ParsedVEX{Format: "openvex", Author: "author", ParserVersion: evidenceapp.OpenVEXParserVersion, StatementCount: 1, ValidStatementCount: 1, StatusSummary: map[string]int{"fixed": 1}, Statements: []evidenceapp.VEXDecisionStatement{{StatementIndex: 1, Vulnerability: "CVE-TEST", Products: []string{"pkg:a"}, Status: "fixed"}}}}
			reader := &vexPreviewReaderFake{artifact: &vexPreviewArtifactAuth{}, snapshot: VEXPreviewSnapshot{TenantID: "tenant", ProductID: "product", ReleaseID: "release", ArtifactID: "artifact", Findings: []VEXPreviewFinding{{ID: "finding", ScanID: "scan", TenantID: "tenant", ReleaseID: "release", Vulnerability: "CVE-TEST", Component: "pkg:a", HasActiveDecision: true}}}}
			mapped := 0
			mapper := func(_ string, _ evidenceapp.ParsedVEX, _ VEXPreviewSnapshot) (VEXPreviewEffects, error) {
				mapped++
				return VEXPreviewEffects{WouldCreate: 1, WouldSupersede: 1, Warnings: []string{"advisory"}, Failures: []evidencedomain.VEXImportIssue{}}, nil
			}
			service, err := NewVEXPreviews(reader, p, mapper, func() time.Time { return at })
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			in := VEXPreviewInput{ReleaseID: " release ", ArtifactID: " artifact ", Format: "openvex", Payload: []byte(`{}`)}
			want := ErrConflict
			switch kind {
			case "scope":
				actor.Scopes = nil
				want = application.ErrForbidden
			case "grant":
				actor.ResourceGrants = nil
				want = application.ErrForbidden
			case "artifact":
				reader.artifact.err = application.ErrForbidden
				want = application.ErrForbidden
			case "foreign":
				reader.snapshot.Findings[0].TenantID = "other"
			case "missing-guard":
				reader.skip = true
			case "overflow":
				reader.snapshot.Findings = make([]VEXPreviewFinding, MaxVEXPreviewFindings+1)
			case "budget":
				reader.snapshot.Findings = make([]VEXPreviewFinding, 9)
				for i := range reader.snapshot.Findings {
					reader.snapshot.Findings[i] = VEXPreviewFinding{ID: string(rune('a' + i)), ScanID: "scan", TenantID: "tenant", ReleaseID: "release", Vulnerability: strings.Repeat("x", 1<<20)}
				}
			case "invalid-finding":
				reader.snapshot.Findings[0].Component = "bad\x00"
			case "invalid-parser":
				p.parsed.ParserVersion = "unknown"
				want = ErrValidation
			case "parser-error":
				p.err = evidenceapp.ErrValidation
				want = ErrValidation
			case "reader":
				reader.err = ErrNotFound
				want = ErrNotFound
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "input":
				in.ReleaseID = strings.Repeat("x", 1025)
				want = ErrValidation
			}
			out, err := service.PreviewVEXImport(ctx, actor, in)
			if kind == "allowed" {
				if err != nil || !out.Advisory || out.DecisionsWouldCreate != 1 || out.DecisionsWouldSupersede != 1 || out.GeneratedAt != at.Truncate(time.Microsecond) || out.SchemaVersion != evidencedomain.VEXImportPreviewSchemaVersion || mapped != 1 || p.calls != 1 || reader.artifact.calls != 1 {
					t.Fatal(out, err)
				}
				return
			}
			if !errors.Is(err, want) || out.TenantID != "" || mapped != 0 {
				t.Fatal(kind, out, err, mapped)
			}
			if (kind == "scope" || kind == "grant" || kind == "artifact" || kind == "reader" || kind == "cancelled" || kind == "input") && p.calls != 0 {
				t.Fatal("denial parsed payload")
			}
		})
	}
	if _, err := NewVEXPreviews(nil, nil, nil, nil); err == nil {
		t.Fatal("missing ports accepted")
	}
}
