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

var errGraphUnit = errors.New("private graph fault")

type graphCommandFixture struct {
	scope        GraphSnapshotScope
	roots        []packagedomain.GraphNode
	items        []GraphSnapshotEvidence
	graphs       []packagedomain.EvidenceGraphSnapshot
	audits       []application.AuditEvent
	phase        string
	reads, limit int
	material     any
	cancel       context.CancelFunc
}

func (f *graphCommandFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !a.HasScope(ScopeEvidenceRead) || f.phase == "authorization" || !r.ScopeOnly && f.phase == "root authorization" {
		return application.ErrForbidden
	}
	return nil
}
func (f *graphCommandFixture) ExecuteGraphSnapshot(ctx context.Context, tenant string, fn func(context.Context, GraphSnapshotTransaction) error) error {
	g, a := len(f.graphs), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errGraphUnit
	}
	if err != nil {
		f.graphs, f.audits = f.graphs[:g], f.audits[:a]
	}
	return err
}
func (f *graphCommandFixture) ReadGraphSnapshotScope(context.Context, string, string, string) (GraphSnapshotScope, error) {
	if f.phase == "scope" {
		return GraphSnapshotScope{}, errGraphUnit
	}
	return f.scope, nil
}
func (f *graphCommandFixture) ReadGraphSnapshotRoots(context.Context, GraphSnapshotScope) ([]packagedomain.GraphNode, error) {
	f.reads++
	if f.phase == "roots" {
		return nil, errGraphUnit
	}
	return f.roots, nil
}
func (f *graphCommandFixture) ReadGraphSnapshotEvidence(_ context.Context, _ GraphSnapshotScope, limit int) ([]GraphSnapshotEvidence, error) {
	f.reads++
	f.limit = limit
	if f.phase == "items" {
		return nil, errGraphUnit
	}
	return f.items, nil
}
func (f *graphCommandFixture) InsertGraphSnapshot(_ context.Context, v packagedomain.EvidenceGraphSnapshot) error {
	if f.phase == "insert" {
		return errGraphUnit
	}
	f.graphs = append(f.graphs, v)
	return nil
}
func (f *graphCommandFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errGraphUnit
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func (f *graphCommandFixture) Hash(v any) (string, error) {
	if f.phase == "hash" {
		return "", errGraphUnit
	}
	if f.phase == "invalid hash" {
		return "sha256:invalid", nil
	}
	f.material = v
	return "sha256:" + strings.Repeat("a", 64), nil
}
func newGraphCommandFixture(t *testing.T) (*GraphSnapshotCommands, *graphCommandFixture, identitydomain.Actor, CreateGraphSnapshotInput) {
	t.Helper()
	f := &graphCommandFixture{scope: GraphSnapshotScope{TenantID: "tenant", ProductID: "product", ReleaseID: "release", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}, roots: []packagedomain.GraphNode{{ID: "product", Type: "product", Label: "Product"}, {ID: "release", Type: "release", Label: "1"}}, items: []GraphSnapshotEvidence{
		{ID: "b", TenantID: "tenant", ProductID: "product", ReleaseID: "release", Title: "B", References: []GraphSnapshotReference{{Type: "opaque", ID: "external"}, {Type: "artifact"}}},
		{ID: "a", TenantID: "tenant", ProductID: "product", ReleaseID: "release", Title: "A"},
	}}
	n := 0
	c, err := NewGraphSnapshotCommands(GraphSnapshotCommandConfig{Transactions: f, Authorizer: f, Hasher: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 3, 12, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{ScopeEvidenceRead}}, CreateGraphSnapshotInput{ProductID: "product", ReleaseID: "release"}
}
func TestGraphCommandDeterministicAdjacencyAndAtomicAudit(t *testing.T) {
	c, f, a, in := newGraphCommandFixture(t)
	v, err := c.CreateGraphSnapshot(t.Context(), a, in)
	wantNodes := []packagedomain.GraphNode{{ID: "product", Type: "product", Label: "Product"}, {ID: "release", Type: "release", Label: "1"}, {ID: "a", Type: "evidence", Label: "A"}, {ID: "b", Type: "evidence", Label: "B"}}
	wantEdges := []packagedomain.GraphEdge{{From: "product", To: "release", Relationship: "has_release"}, {From: "release", To: "a", Relationship: "has_evidence"}, {From: "release", To: "b", Relationship: "has_evidence"}, {From: "b", To: "external", Relationship: "references_opaque"}}
	if err != nil || !reflect.DeepEqual(v.Nodes, wantNodes) || !reflect.DeepEqual(v.Edges, wantEdges) || v.SchemaVersion != packagedomain.EvidenceGraphSnapshotVersion || v.CreatedAt.Nanosecond() != 123456000 {
		t.Fatal("graph contract changed", v, err)
	}
	if f.limit != MaxEvidenceGraphNodes-2 || len(f.graphs) != 1 || len(f.audits) != 1 || f.audits[0].PayloadHash != v.GraphHash || f.audits[0].SubjectID != v.ID || f.audits[0].ActorID != a.KeyID || f.audits[0].EntryType != "evidence_graph_snapshot.created" {
		t.Fatal("graph/audit not atomic", f.audits)
	}
	if len(v.Limitations) != 1 || !strings.Contains(v.Limitations[0], "stored Evydence adjacency") {
		t.Fatal("graph overclaims provenance")
	}
	v.Nodes[0].Label = "changed"
	v.Edges[0].From = "changed"
	v.Limitations[0] = "changed"
	if f.graphs[0].Nodes[0].Label == "changed" || f.graphs[0].Edges[0].From == "changed" || f.graphs[0].Limitations[0] == "changed" || f.roots[0].Label == "changed" {
		t.Fatal("caller mutated persisted graph")
	}
}
func TestGraphCommandFailsClosedAndReturnsNoUncommittedProjection(t *testing.T) {
	for _, phase := range []string{"authorization", "root authorization", "scope", "roots", "items", "hash", "invalid hash", "insert", "audit", "commit", "cancel", "foreign scope", "mismatched root", "foreign evidence", "wrong selection", "duplicate evidence", "oversized label", "too many edges", "too many nodes"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := newGraphCommandFixture(t)
			f.phase = phase
			want := errGraphUnit
			ctx := t.Context()
			switch phase {
			case "authorization", "root authorization":
				want = application.ErrForbidden
			case "invalid hash":
				want = ErrValidation
			case "foreign scope":
				f.scope.TenantID = "other"
				want = ErrNotFound
			case "mismatched root":
				f.scope.Resources.ProductID = "other"
				want = ErrNotFound
			case "foreign evidence":
				f.items[0].TenantID = "other"
				want = ErrNotFound
			case "wrong selection":
				f.items[0].ReleaseID = "other"
				want = ErrNotFound
			case "duplicate evidence":
				f.items[0].ID = f.items[1].ID
				want = ErrConflict
			case "oversized label":
				f.items[0].Title = strings.Repeat("x", MaxGraphSnapshotLabelBytes+1)
				want = ErrValidation
			case "too many edges":
				f.items[0].References = make([]GraphSnapshotReference, MaxEvidenceGraphEdges)
				for i := range f.items[0].References {
					f.items[0].References[i] = GraphSnapshotReference{Type: "opaque", ID: "ref"}
				}
				want = ErrValidation
			case "too many nodes":
				f.items = make([]GraphSnapshotEvidence, MaxEvidenceGraphNodes)
				want = ErrValidation
			case "cancel":
				ctx, f.cancel = context.WithCancel(t.Context())
				defer f.cancel()
				want = context.Canceled
			}
			v, err := c.CreateGraphSnapshot(ctx, a, in)
			if !errors.Is(err, want) || !reflect.DeepEqual(v, packagedomain.EvidenceGraphSnapshot{}) || len(f.graphs) != 0 || len(f.audits) != 0 {
				t.Fatal("graph escaped failure", v, err)
			}
		})
	}
}
func TestGraphCommandReplayGuardReadsOnlyCurrentOwnership(t *testing.T) {
	c, f, a, in := newGraphCommandFixture(t)
	if err := c.AuthorizeCreateGraphSnapshot(t.Context(), a, in); err != nil || f.reads != 0 || len(f.graphs) != 0 || len(f.audits) != 0 {
		t.Fatal("replay guard reads private graph metadata or writes", err)
	}
	f.phase = "root authorization"
	if err := c.AuthorizeCreateGraphSnapshot(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("grant removal ignored", err)
	}
}
func TestGraphInputBoundsBeforeNormalization(t *testing.T) {
	for _, in := range []CreateGraphSnapshotInput{{}, {ProductID: strings.Repeat(" ", 1025) + "product"}, {ReleaseID: "bad\x00"}, {ProductID: string([]byte{0xff})}} {
		if _, err := NormalizeGraphSnapshotInput(in); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid graph input accepted", err)
		}
	}
	v, err := NormalizeGraphSnapshotInput(CreateGraphSnapshotInput{ReleaseID: " release "})
	if err != nil || v.ReleaseID != "release" || v.ProductID != "" {
		t.Fatal("optional product semantics changed", v, err)
	}
}

func TestGraphCommandRejectsEscapedOutputBeyondAdjacencyBudget(t *testing.T) {
	for _, escaped := range []bool{false, true} {
		t.Run(fmt.Sprint(escaped), func(t *testing.T) {
			c, f, a, in := newGraphCommandFixture(t)
			label := "x"
			if escaped {
				label = "\x01"
			}
			f.items = make([]GraphSnapshotEvidence, 13)
			for i := range f.items {
				f.items[i] = GraphSnapshotEvidence{ID: fmt.Sprintf("item-%02d", i), TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: strings.Repeat(label, MaxGraphSnapshotLabelBytes)}
			}
			v, err := c.CreateGraphSnapshot(t.Context(), a, in)
			if escaped {
				if !errors.Is(err, ErrValidation) || !reflect.DeepEqual(v, packagedomain.EvidenceGraphSnapshot{}) || len(f.graphs)+len(f.audits) != 0 {
					t.Fatal("encoded adjacency overflow published a graph", v.ID, err)
				}
			} else if err != nil || len(v.Nodes) != len(f.items)+len(f.roots) || len(f.graphs) != 1 || len(f.audits) != 1 {
				t.Fatal("bounded unescaped adjacency was rejected", v.ID, err)
			}
		})
	}
}

func TestGraphCommandExactEdgeLimitDoesNotTruncate(t *testing.T) {
	c, f, a, in := newGraphCommandFixture(t)
	f.items = f.items[:1]
	f.items[0].References = make([]GraphSnapshotReference, MaxEvidenceGraphEdges-2)
	for i := range f.items[0].References {
		f.items[0].References[i] = GraphSnapshotReference{Type: "opaque", ID: "external"}
	}
	v, err := c.CreateGraphSnapshot(t.Context(), a, in)
	if err != nil || len(v.Edges) != MaxEvidenceGraphEdges || len(f.graphs) != 1 || len(f.audits) != 1 {
		t.Fatal("exact edge limit changed", len(v.Edges), err)
	}
	f.items[0].References = append(f.items[0].References, GraphSnapshotReference{Type: "opaque", ID: "overflow"})
	v, err = c.CreateGraphSnapshot(t.Context(), a, in)
	if !errors.Is(err, ErrValidation) || !reflect.DeepEqual(v, packagedomain.EvidenceGraphSnapshot{}) || len(f.graphs) != 1 || len(f.audits) != 1 {
		t.Fatal("overflow truncated or published effects", v.ID, err)
	}
}

func TestGraphCommandEmptySelectionsRetainOnlyRequestedRoots(t *testing.T) {
	for _, kind := range []string{"product", "release", "both"} {
		t.Run(kind, func(t *testing.T) {
			c, f, a, in := newGraphCommandFixture(t)
			f.items = nil
			edges := 0
			switch kind {
			case "product":
				in.ReleaseID, f.scope.ReleaseID, f.scope.Resources.ReleaseID = "", "", ""
				f.roots = f.roots[:1]
			case "release":
				in.ProductID, f.scope.ProductID = "", ""
				f.roots = f.roots[1:]
			case "both":
				edges = 1
			}
			v, err := c.CreateGraphSnapshot(t.Context(), a, in)
			if err != nil || !reflect.DeepEqual(v.Nodes, f.roots) || v.ProductID != in.ProductID || v.ReleaseID != in.ReleaseID || v.Edges == nil || len(v.Edges) != edges || f.limit != MaxEvidenceGraphNodes-len(f.roots) || len(f.graphs) != 1 || len(f.audits) != 1 {
				t.Fatal("empty selection inferred or lost roots", v, err)
			}
			raw, err := EncodeGraphSnapshot(v)
			if err != nil || edges == 0 && !strings.Contains(string(raw), `"edges":[]`) {
				t.Fatal("empty edges changed public shape", string(raw), err)
			}
		})
	}
}
