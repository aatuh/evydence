package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func (l *Ledger) authorizeGraphSnapshotLocked(a domain.Actor, in packageapp.CreateGraphSnapshotInput) (packageapp.GraphSnapshotScope, error) {
	if err := l.ensureScopeLocked(a.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
		return packageapp.GraphSnapshotScope{}, err
	}
	p := in.ProductID
	if in.ReleaseID != "" {
		parent := l.releases[in.ReleaseID].ProductID
		if p != "" && p != parent {
			return packageapp.GraphSnapshotScope{}, ErrNotFound
		}
		p = parent
	}
	if err := l.ensureScopeLocked(a.TenantID, p, "", ""); err != nil {
		return packageapp.GraphSnapshotScope{}, err
	}
	if err := l.authorizeResourceLocked(a, ScopeEvidenceRead, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
		return packageapp.GraphSnapshotScope{}, err
	}
	return packageapp.GraphSnapshotScope{TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Resources: application.ResourceReferences{ProductID: p, ReleaseID: in.ReleaseID}}, nil
}
func (l *Ledger) AuthorizeCreateGraphSnapshot(ctx context.Context, a domain.Actor, in CreateGraphSnapshotInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeEvidenceRead); err != nil {
		return err
	}
	v, err := packageapp.NormalizeGraphSnapshotInput(packageapp.CreateGraphSnapshotInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.authorizeGraphSnapshotLocked(a, v)
	return err
}
func graphSnapshotLegacyRecord(v packagedomain.EvidenceGraphSnapshot) domain.EvidenceGraphSnapshot {
	nodes := make([]domain.GraphNode, len(v.Nodes))
	for i, n := range v.Nodes {
		nodes[i] = domain.GraphNode{ID: n.ID, Type: n.Type, Label: n.Label}
	}
	edges := make([]domain.GraphEdge, len(v.Edges))
	for i, e := range v.Edges {
		edges[i] = domain.GraphEdge{From: e.From, To: e.To, Relationship: e.Relationship}
	}
	return domain.EvidenceGraphSnapshot{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Nodes: nodes, Edges: edges, GraphHash: v.GraphHash, Limitations: append([]string(nil), v.Limitations...), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
