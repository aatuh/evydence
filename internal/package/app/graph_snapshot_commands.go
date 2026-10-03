package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const (
	ScopeEvidenceRead                  = "evidence:read"
	MaxEvidenceGraphNodes              = 4096
	MaxEvidenceGraphEdges              = 8192
	MaxGraphSnapshotIDBytes            = 1024
	MaxGraphSnapshotLabelBytes         = 64 << 10
	MaxGraphSnapshotReferenceTypeBytes = 128
)

type CreateGraphSnapshotInput struct{ ProductID, ReleaseID string }

// Requested coordinates retain selection and root-node semantics; Resources
// contains the current, tenant-validated release parent used for authorization.
type GraphSnapshotScope struct {
	TenantID, ProductID, ReleaseID string
	Resources                      application.ResourceReferences
}
type GraphSnapshotReference struct{ Type, ID string }
type GraphSnapshotEvidence struct {
	ID, TenantID, ProductID, ReleaseID, Title string
	References                                []GraphSnapshotReference
}
type GraphSnapshotReader interface {
	ReadGraphSnapshotScope(context.Context, string, string, string) (GraphSnapshotScope, error)
	ReadGraphSnapshotRoots(context.Context, GraphSnapshotScope) ([]packagedomain.GraphNode, error)
	ReadGraphSnapshotEvidence(context.Context, GraphSnapshotScope, int) ([]GraphSnapshotEvidence, error)
}
type GraphSnapshotTransaction interface {
	GraphSnapshotReader
	InsertGraphSnapshot(context.Context, packagedomain.EvidenceGraphSnapshot) error
	application.Authorizer
	application.AuditAppender
}
type GraphSnapshotTransactions interface {
	ExecuteGraphSnapshot(context.Context, string, func(context.Context, GraphSnapshotTransaction) error) error
}
type GraphSnapshotHasher interface{ Hash(any) (string, error) }
type GraphSnapshotCommandConfig struct {
	Transactions GraphSnapshotTransactions
	Authorizer   application.Authorizer
	Hasher       GraphSnapshotHasher
	Clock        application.Clock
	IDs          application.IDGenerator
}
type GraphSnapshotCommands struct{ config GraphSnapshotCommandConfig }

func NewGraphSnapshotCommands(c GraphSnapshotCommandConfig) (*GraphSnapshotCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Hasher == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &GraphSnapshotCommands{c}, nil
}
func graphText(v string, n int) bool {
	return len(v) <= n && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func graphID(v string) bool {
	return v != "" && strings.TrimSpace(v) == v && graphText(v, MaxGraphSnapshotIDBytes)
}
func NormalizeGraphSnapshotInput(in CreateGraphSnapshotInput) (CreateGraphSnapshotInput, error) {
	if !graphText(in.ProductID, MaxGraphSnapshotIDBytes) || !graphText(in.ReleaseID, MaxGraphSnapshotIDBytes) {
		return in, ErrValidation
	}
	in.ProductID, in.ReleaseID = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	if in.ProductID == "" && in.ReleaseID == "" {
		return in, ErrValidation
	}
	return in, nil
}
func ValidateGraphSnapshotScope(tenant string, in CreateGraphSnapshotInput, s GraphSnapshotScope) error {
	r := s.Resources
	if !graphID(tenant) || s.TenantID != tenant || s.ProductID != in.ProductID || s.ReleaseID != in.ReleaseID || !graphID(r.ProductID) || r.ReleaseID != in.ReleaseID || r != (application.ResourceReferences{ProductID: r.ProductID, ReleaseID: in.ReleaseID}) || in.ProductID != "" && r.ProductID != in.ProductID {
		return ErrNotFound
	}
	return nil
}
func (s *GraphSnapshotCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateGraphSnapshotInput) (CreateGraphSnapshotInput, error) {
	if s == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	in, err := NormalizeGraphSnapshotInput(in)
	if err != nil {
		return in, err
	}
	if !graphID(a.TenantID) || !graphID(auditActorID(a)) {
		return in, application.ErrUnauthorized
	}
	return in, s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceRead, ScopeOnly: true})
}
func readAuthorizedGraphScope(ctx context.Context, tx GraphSnapshotTransaction, a identitydomain.Actor, in CreateGraphSnapshotInput) (GraphSnapshotScope, error) {
	if tx == nil {
		return GraphSnapshotScope{}, ErrValidation
	}
	scope, err := tx.ReadGraphSnapshotScope(ctx, a.TenantID, in.ProductID, in.ReleaseID)
	if err != nil {
		return scope, err
	}
	if err := ValidateGraphSnapshotScope(a.TenantID, in, scope); err != nil {
		return GraphSnapshotScope{}, err
	}
	return scope, tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceRead, Resources: scope.Resources})
}
func (s *GraphSnapshotCommands) AuthorizeCreateGraphSnapshot(ctx context.Context, a identitydomain.Actor, in CreateGraphSnapshotInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteGraphSnapshot(ctx, a.TenantID, func(ctx context.Context, tx GraphSnapshotTransaction) error {
		_, err := readAuthorizedGraphScope(ctx, tx, a, in)
		if err != nil {
			return err
		}
		return contextError(ctx)
	})
}
func (s *GraphSnapshotCommands) CreateGraphSnapshot(ctx context.Context, a identitydomain.Actor, in CreateGraphSnapshotInput) (packagedomain.EvidenceGraphSnapshot, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return packagedomain.EvidenceGraphSnapshot{}, err
	}
	var out packagedomain.EvidenceGraphSnapshot
	err = s.config.Transactions.ExecuteGraphSnapshot(ctx, a.TenantID, func(ctx context.Context, tx GraphSnapshotTransaction) error {
		scope, err := readAuthorizedGraphScope(ctx, tx, a, in)
		if err != nil {
			return err
		}
		roots, err := tx.ReadGraphSnapshotRoots(ctx, scope)
		if err != nil {
			return err
		}
		rootCount := 0
		if in.ProductID != "" {
			rootCount++
		}
		if in.ReleaseID != "" {
			rootCount++
		}
		items, err := tx.ReadGraphSnapshotEvidence(ctx, scope, MaxEvidenceGraphNodes-rootCount)
		if err != nil {
			return err
		}
		out, err = BuildGraphSnapshotProjection(scope, roots, items)
		if err != nil {
			return err
		}
		out.GraphHash, err = s.config.Hasher.Hash(GraphSnapshotHashMaterial(out))
		if err != nil {
			return err
		}
		if !strings.HasPrefix(out.GraphHash, "sha256:") {
			return ErrValidation
		}
		if raw, err := hex.DecodeString(strings.TrimPrefix(out.GraphHash, "sha256:")); err != nil || len(raw) != 32 {
			return ErrValidation
		}
		out.ID = s.config.IDs.NewID("grf")
		out.CreatedAt = s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !graphID(out.ID) || out.CreatedAt.IsZero() || out.CreatedAt.Year() < 1 || out.CreatedAt.Year() > 9999 {
			return ErrValidation
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertGraphSnapshot(ctx, CloneGraphSnapshot(out)); err != nil {
			return err
		}
		e := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "evidence_graph_snapshot.created", SubjectType: "evidence_graph_snapshot", SubjectID: out.ID, ActorType: auditActorType(a), ActorID: auditActorID(a), PayloadHash: out.GraphHash, OccurredAt: out.CreatedAt}
		if !graphID(e.ID) {
			return ErrValidation
		}
		if _, err := tx.AppendAudit(ctx, e); err != nil {
			return err
		}
		return contextError(ctx)
	})
	if err != nil {
		return packagedomain.EvidenceGraphSnapshot{}, err
	}
	return CloneGraphSnapshot(out), nil
}

// This pure builder is shared by durable commands and explicit local-memory
// operation. Subject references remain recorded adjacency, not verified objects.
func BuildGraphSnapshotProjection(s GraphSnapshotScope, roots []packagedomain.GraphNode, items []GraphSnapshotEvidence) (packagedomain.EvidenceGraphSnapshot, error) {
	var empty packagedomain.EvidenceGraphSnapshot
	if err := ValidateGraphSnapshotScope(s.TenantID, CreateGraphSnapshotInput{s.ProductID, s.ReleaseID}, s); err != nil {
		return empty, err
	}
	expected := []packagedomain.GraphNode{}
	if s.ProductID != "" {
		expected = append(expected, packagedomain.GraphNode{ID: s.ProductID, Type: "product"})
	}
	if s.ReleaseID != "" {
		expected = append(expected, packagedomain.GraphNode{ID: s.ReleaseID, Type: "release"})
	}
	if len(roots) != len(expected) {
		return empty, ErrNotFound
	}
	if len(roots)+len(items) > MaxEvidenceGraphNodes {
		return empty, ErrValidation
	}
	nodes := make([]packagedomain.GraphNode, 0, len(roots)+len(items))
	edges := []packagedomain.GraphEdge{}
	bytes := 0
	for i, n := range roots {
		if n.ID != expected[i].ID || n.Type != expected[i].Type {
			return empty, ErrNotFound
		}
		if !graphText(n.Label, MaxGraphSnapshotLabelBytes) {
			return empty, ErrValidation
		}
		bytes += len(n.ID) + len(n.Type) + len(n.Label)
		nodes = append(nodes, n)
	}
	if s.ProductID != "" && s.ReleaseID != "" {
		edges = append(edges, packagedomain.GraphEdge{From: s.ProductID, To: s.ReleaseID, Relationship: "has_release"})
	}
	items = append([]GraphSnapshotEvidence(nil), items...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	for i, v := range items {
		if v.TenantID != s.TenantID || s.ProductID != "" && v.ProductID != s.ProductID || s.ReleaseID != "" && v.ReleaseID != s.ReleaseID || v.ProductID != "" && v.ProductID != s.Resources.ProductID {
			return empty, ErrNotFound
		}
		if i > 0 && v.ID == items[i-1].ID {
			return empty, ErrConflict
		}
		if !graphID(v.ID) || v.ProductID != "" && !graphID(v.ProductID) || v.ReleaseID != "" && !graphID(v.ReleaseID) || !graphText(v.Title, MaxGraphSnapshotLabelBytes) || len(v.References) > MaxEvidenceGraphEdges {
			return empty, ErrValidation
		}
		bytes += len(v.ID) + len(v.Title) + len(v.ProductID) + len(v.ReleaseID)
		if bytes > MaxGeneratedReportBytes {
			return empty, ErrValidation
		}
		nodes = append(nodes, packagedomain.GraphNode{ID: v.ID, Type: "evidence", Label: v.Title})
		parent := v.ReleaseID
		if parent == "" {
			parent = v.ProductID
		}
		if parent != "" {
			if len(edges) == MaxEvidenceGraphEdges {
				return empty, ErrValidation
			}
			edges = append(edges, packagedomain.GraphEdge{From: parent, To: v.ID, Relationship: "has_evidence"})
		}
		for _, ref := range v.References {
			if !graphText(ref.Type, MaxGraphSnapshotReferenceTypeBytes) || !graphText(ref.ID, MaxGraphSnapshotIDBytes) {
				return empty, ErrValidation
			}
			bytes += len(ref.Type) + len(ref.ID)
			if bytes > MaxGeneratedReportBytes {
				return empty, ErrValidation
			}
			if ref.ID == "" {
				continue
			}
			if ref.Type == "" || len(edges) == MaxEvidenceGraphEdges {
				return empty, ErrValidation
			}
			edges = append(edges, packagedomain.GraphEdge{From: v.ID, To: ref.ID, Relationship: "references_" + ref.Type})
		}
	}
	v := packagedomain.EvidenceGraphSnapshot{TenantID: s.TenantID, ProductID: s.ProductID, ReleaseID: s.ReleaseID, Nodes: nodes, Edges: edges, Limitations: []string{"Snapshot includes stored Evydence adjacency only; absence of a node is not proof that evidence does not exist elsewhere."}, SchemaVersion: packagedomain.EvidenceGraphSnapshotVersion}
	raw, err := json.Marshal(GraphSnapshotHashMaterial(v))
	if err != nil {
		return empty, err
	}
	if len(raw) > MaxGeneratedReportBytes {
		return empty, ErrValidation
	}
	return v, nil
}
func GraphSnapshotHashMaterial(v packagedomain.EvidenceGraphSnapshot) map[string]any {
	nodes := make([]map[string]string, len(v.Nodes))
	for i, n := range v.Nodes {
		nodes[i] = map[string]string{"id": n.ID, "type": n.Type, "label": n.Label}
	}
	edges := make([]map[string]string, len(v.Edges))
	for i, e := range v.Edges {
		edges[i] = map[string]string{"from": e.From, "to": e.To, "relationship": e.Relationship}
	}
	return map[string]any{"nodes": nodes, "edges": edges}
}
func CloneGraphSnapshot(v packagedomain.EvidenceGraphSnapshot) packagedomain.EvidenceGraphSnapshot {
	v.Nodes = append([]packagedomain.GraphNode{}, v.Nodes...)
	v.Edges = append([]packagedomain.GraphEdge{}, v.Edges...)
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}

func EncodeGraphSnapshot(v packagedomain.EvidenceGraphSnapshot) ([]byte, error) {
	m := GraphSnapshotHashMaterial(v)
	m["id"], m["tenant_id"], m["graph_hash"] = v.ID, v.TenantID, v.GraphHash
	m["limitations"], m["schema_version"], m["created_at"] = v.Limitations, v.SchemaVersion, v.CreatedAt
	if v.ProductID != "" {
		m["product_id"] = v.ProductID
	}
	if v.ReleaseID != "" {
		m["release_id"] = v.ReleaseID
	}
	return json.Marshal(m)
}
