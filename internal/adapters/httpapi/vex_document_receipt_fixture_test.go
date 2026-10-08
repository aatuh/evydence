package httpapi

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

// Only the repository-free synchronous characterization supplies its actual
// immutable upload receipt. This is not a current storage snapshot, and does
// not fabricate a completed report or claim to execute a native worker job.
type immutableVEXDocumentReceiptFixture struct {
	evidenceReadFixture
	point evidencequery.VEXDocumentPoint
}

func (f immutableVEXDocumentReceiptFixture) GetVEXDocumentPoint(ctx context.Context, tenant, id string) (evidencequery.VEXDocumentPoint, error) {
	var zero evidencequery.VEXDocumentPoint
	if ctx == nil {
		return zero, evidencequery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if f.point.Document.ID != strings.TrimSpace(id) || f.point.Document.TenantID != tenant {
		return zero, evidencequery.ErrNotFound
	}
	out := f.point
	out.Document.StatusSummary = maps.Clone(out.Document.StatusSummary)
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return out, nil
}

func (f immutableVEXDocumentReceiptFixture) GetVEXDocument(ctx context.Context, actor domain.Actor, id string) (evidencedomain.VEXDocument, error) {
	query, err := evidencequery.NewVEXPoints(f)
	if err != nil {
		return evidencedomain.VEXDocument{}, err
	}
	value, err := query.GetVEXDocument(ctx, actor, id)
	return value, legacyParsedPointError(err)
}

func TestVEXDocumentReceiptUsesFocusedIdentityPolicyAndDetachedMetadata(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	document := evidencedomain.VEXDocument{ID: "vex", TenantID: "tenant", EvidenceID: "source", ReleaseID: "release", Format: "openvex", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}, SchemaVersion: "vex-document.v1", CreatedAt: time.Date(2026, 10, 7, 15, 0, 0, 0, time.UTC)}
	reader := immutableVEXDocumentReceiptFixture{evidenceReadFixture: evidenceReadFixture{catalogFixtureCommands{ledger: ledger}}, point: evidencequery.VEXDocumentPoint{Document: document, ProductID: "product"}}
	actor := domain.Actor{TenantID: "tenant", UserID: "reader", Scopes: []string{"evidence:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"evidence:read"}}}}
	value, err := reader.GetVEXDocument(t.Context(), actor, " vex ")
	if err != nil || !reflect.DeepEqual(value, document) {
		t.Fatal("receipt lost recorded metadata or focused authority", value, err)
	}
	value.StatusSummary["fixed"] = -1
	if document.StatusSummary["fixed"] != 1 {
		t.Fatal("receipt returned an alias of recorded metadata")
	}
	for _, id := range []string{"missing", "source", ""} {
		if value, err := reader.GetVEXDocument(t.Context(), actor, id); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(value, evidencedomain.VEXDocument{}) {
			t.Fatal("receipt accepted a different document identity", value, err)
		}
	}
	denied := actor
	denied.TenantID = "foreign"
	if _, err := reader.GetVEXDocument(t.Context(), denied, "vex"); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("receipt reader crossed tenants", err)
	}
	denied = actor
	denied.ResourceGrants = nil
	if _, err := reader.GetVEXDocument(t.Context(), denied, "vex"); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("receipt retained removed grants", err)
	}
	denied.ResourceGrants = []domain.ResourceGrant{{ResourceType: "release", ResourceID: "foreign", Scopes: []string{"evidence:read"}}}
	if _, err := reader.GetVEXDocument(t.Context(), denied, "vex"); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("receipt accepted an unrelated release grant", err)
	}
	var absent context.Context
	if _, err := reader.GetVEXDocument(absent, actor, "vex"); !errors.Is(err, app.ErrValidation) {
		t.Fatal("receipt accepted a nil context", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := reader.GetVEXDocument(ctx, actor, "vex"); !errors.Is(err, context.Canceled) || value.ID != "" {
		t.Fatal("receipt returned data after cancellation", value, err)
	}
	query, err := evidencequery.NewVEXPoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := query.GetVEXImportReport(t.Context(), actor, "vex"); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(value, evidencedomain.VEXImportReport{}) {
		t.Fatal("document receipt invented a completed report", value, err)
	}
	reader.point.Document.SchemaVersion = ""
	if _, err := reader.GetVEXDocument(t.Context(), actor, "vex"); !errors.Is(err, app.ErrConflict) {
		t.Fatal("receipt bypassed the focused document shape check", err)
	}
}
