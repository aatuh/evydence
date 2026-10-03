package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Only citation metadata is available to the command, never raw evidence.
type summaryCommandFixture struct {
	scope               EvidenceSummaryScope
	items               []EvidenceSummaryItem
	input               CreateEvidenceSummaryInput
	summaries           []packagedomain.EvidenceSummary
	audits              []application.AuditEvent
	phase               string
	reads, transactions int
	cancel              context.CancelFunc
}

var errSummaryUnit = errors.New("private summary fault")

func (f *summaryCommandFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.TenantID == "" || a.KeyID == "" && a.UserID == "" {
		return application.ErrUnauthorized
	}
	if r.Scope != ScopeReportRead || !a.HasScope(r.Scope) || f.phase == "authorization" || f.phase == "root authorization" && !r.ScopeOnly {
		return application.ErrForbidden
	}
	return nil
}
func (f *summaryCommandFixture) ExecuteEvidenceSummary(ctx context.Context, tenant string, fn func(context.Context, EvidenceSummaryTransaction) error) error {
	f.transactions++
	if tenant != f.scope.TenantID && f.phase != "foreign scope" {
		return ErrNotFound
	}
	r, a := len(f.summaries), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errSummaryUnit
	}
	if err != nil {
		f.summaries = f.summaries[:r]
		f.audits = f.audits[:a]
	}
	return err
}
func (f *summaryCommandFixture) ReadEvidenceSummaryScope(_ context.Context, tenant, kind, id string) (EvidenceSummaryScope, error) {
	f.reads++
	if f.phase == "scope read" {
		return EvidenceSummaryScope{}, errSummaryUnit
	}
	if tenant != f.scope.TenantID && f.phase != "foreign scope" || kind != f.scope.SubjectType || id != f.scope.SubjectID {
		return EvidenceSummaryScope{}, ErrNotFound
	}
	return f.scope, nil
}
func (f *summaryCommandFixture) ReadEvidenceSummaryItems(_ context.Context, s EvidenceSummaryScope, ids []string) ([]EvidenceSummaryItem, error) {
	f.reads++
	if f.phase == "items read" {
		return nil, errSummaryUnit
	}
	if s.TenantID != f.scope.TenantID {
		return nil, ErrNotFound
	}
	f.input.EvidenceIDs = append([]string(nil), ids...)
	return append([]EvidenceSummaryItem(nil), f.items...), nil
}
func (f *summaryCommandFixture) InsertEvidenceSummary(_ context.Context, v packagedomain.EvidenceSummary) error {
	if f.phase == "insert" {
		return errSummaryUnit
	}
	f.summaries = append(f.summaries, v)
	return nil
}
func (f *summaryCommandFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errSummaryUnit
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel after audit" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func newSummaryCommandFixture(t *testing.T) (*EvidenceSummaryCommands, *summaryCommandFixture, identitydomain.Actor, CreateEvidenceSummaryInput) {
	t.Helper()
	refs := application.ResourceReferences{ProductID: "product", ReleaseID: "release"}
	f := &summaryCommandFixture{scope: EvidenceSummaryScope{TenantID: "tenant", SubjectType: "release", SubjectID: "release", Resources: refs, Filter: refs}, items: []EvidenceSummaryItem{
		{ID: "b", TenantID: "tenant", Resources: refs, Type: "sbom", Title: "SBOM", CanonicalHash: "sha256:bbb"},
		{ID: "a", TenantID: "tenant", Resources: refs, Type: "build", Title: "Build", CanonicalHash: "sha256:aaa"},
	}}
	n := 0
	c, err := NewEvidenceSummaryCommands(EvidenceSummaryCommandConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC) }), IDs: application.IDGeneratorFunc(func(prefix string) string { n++; return fmt.Sprintf("%s-%d", prefix, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{ScopeReportRead}}, CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: "release"}
}
func TestSummaryCommandDeterministicCitationsAndAtomicAudit(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint(explicit), func(t *testing.T) {
			c, f, a, in := newSummaryCommandFixture(t)
			if explicit {
				in.EvidenceIDs = []string{" b ", "a"}
			}
			v, err := c.CreateEvidenceSummary(t.Context(), a, in)
			if err != nil || v.Summary != "Technical evidence recorded for release release: Build; SBOM." || !reflect.DeepEqual(v.EvidenceIDs, []string{"a", "b"}) || len(v.Citations) != 2 || v.Citations[0].CanonicalHash != "sha256:aaa" {
				t.Fatal("summary facts/order changed", v, err)
			}
			if len(f.summaries) != 1 || len(f.audits) != 1 || f.audits[0].EntryType != "evidence_summary.created" || f.audits[0].ActorID != a.KeyID || f.audits[0].SubjectID != v.ID || v.SchemaVersion != packagedomain.EvidenceSummaryVersion {
				t.Fatal("summary/audit mismatch")
			}
			if len(v.Assumptions) == 0 || len(v.Limitations) == 0 {
				t.Fatal("summary lost limitations")
			}
			encoded, err := EncodeEvidenceSummary(v)
			if err != nil || !strings.Contains(string(encoded), `"evidence_ids"`) || !strings.Contains(string(encoded), `"canonical_hash"`) || strings.Contains(string(encoded), `"CanonicalHash"`) {
				t.Fatal("public summary JSON names changed", err)
			}
			v.EvidenceIDs[0] = "mutated"
			v.Citations[0].Title = "mutated"
			v.Limitations[0] = "mutated"
			if f.summaries[0].EvidenceIDs[0] != "a" || f.summaries[0].Citations[0].Title != "Build" || f.summaries[0].Limitations[0] == "mutated" {
				t.Fatal("response mutates stored summary")
			}
		})
	}
}
func TestSummaryCommandFailsClosedBeforePublishing(t *testing.T) {
	for _, phase := range []string{"authorization", "root authorization", "scope read", "items read", "foreign scope", "foreign item", "wrong refs", "missing explicit", "all explicit missing", "duplicate projection", "empty", "too many", "oversized title", "oversized output", "insert", "audit", "commit", "cancel after audit"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := newSummaryCommandFixture(t)
			f.phase = phase
			want := errSummaryUnit
			ctx := t.Context()
			switch phase {
			case "authorization", "root authorization":
				want = application.ErrForbidden
			case "foreign scope":
				f.scope.TenantID = "other"
				want = ErrNotFound
			case "foreign item":
				f.items[0].TenantID = "other"
				want = ErrNotFound
			case "wrong refs":
				f.items[0].Resources.ReleaseID = "other"
				want = ErrValidation
			case "missing explicit":
				in.EvidenceIDs = []string{"a", "missing"}
				want = ErrNotFound
			case "all explicit missing":
				in.EvidenceIDs = []string{"missing"}
				f.items = nil
				want = ErrNotFound
			case "duplicate projection":
				f.items[0].ID = f.items[1].ID
				want = ErrConflict
			case "empty":
				f.items = nil
				want = ErrValidation
			case "too many":
				f.items = make([]EvidenceSummaryItem, 513)
				want = ErrValidation
			case "oversized title":
				f.items[0].Title = strings.Repeat("x", 65537)
				want = ErrValidation
			case "oversized output":
				f.items = make([]EvidenceSummaryItem, 100)
				for i := range f.items {
					f.items[i] = EvidenceSummaryItem{ID: fmt.Sprint(i), TenantID: "tenant", Resources: f.scope.Resources, Type: "note", Title: strings.Repeat("x", 30000), CanonicalHash: "sha256:aaa"}
				}
				want = ErrValidation
			case "cancel after audit":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				f.cancel = cancel
				want = context.Canceled
			}
			v, err := c.CreateEvidenceSummary(ctx, a, in)
			if !errors.Is(err, want) || v.ID != "" || len(f.summaries)+len(f.audits) != 0 {
				t.Fatalf("partial/invalid summary: state=%s err=%v want=%v writes=%d", v.ID, err, want, len(f.summaries)+len(f.audits))
			}
			if phase == "authorization" && f.reads != 0 || phase == "root authorization" && f.reads != 1 {
				t.Fatal("permission denial still read citations")
			}
		})
	}
}
func TestSummaryCommandRejectsAmbiguousAndOversizedInputsBeforeTransaction(t *testing.T) {
	for _, variant := range []string{"type", "id", "unknown", "duplicate", "blank item", "long item", "invalid utf8", "nul", "too many", "no actor", "canceled"} {
		t.Run(variant, func(t *testing.T) {
			c, f, a, in := newSummaryCommandFixture(t)
			want := ErrValidation
			ctx := t.Context()
			switch variant {
			case "type":
				in.SubjectType = ""
			case "id":
				in.SubjectID = " "
			case "unknown":
				in.SubjectType = "unknown"
			case "duplicate":
				in.EvidenceIDs = []string{"a", " a "}
			case "blank item":
				in.EvidenceIDs = []string{" "}
			case "long item":
				in.EvidenceIDs = []string{strings.Repeat("x", 1025)}
			case "invalid utf8":
				in.SubjectID = string([]byte{0xff})
			case "nul":
				in.SubjectID = "release\x00"
			case "too many":
				in.EvidenceIDs = make([]string, 513)
			case "no actor":
				a.KeyID = ""
				want = application.ErrUnauthorized
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			}
			if _, err := c.CreateEvidenceSummary(ctx, a, in); !errors.Is(err, want) || f.transactions != 0 || f.reads != 0 {
				t.Fatal("invalid request reached summary transaction", err)
			}
		})
	}
}
func TestSummaryReplayAuthorizationIsReadOnlyAndChecksRoot(t *testing.T) {
	c, f, a, in := newSummaryCommandFixture(t)
	if err := c.AuthorizeCreateEvidenceSummary(t.Context(), a, in); err != nil || f.reads != 1 || len(f.summaries)+len(f.audits) != 0 {
		t.Fatal("summary replay guard writes or reads citations", err)
	}
	f.phase = "root authorization"
	if err := c.AuthorizeCreateEvidenceSummary(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("summary replay bypassed root authority", err)
	}
}
