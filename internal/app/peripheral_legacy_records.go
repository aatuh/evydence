package app

import (
	"github.com/aatuh/evydence/internal/domain"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Detached transport/persistence translations; no aggregate state or commands.

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

func SaaSProfileLegacyRecord(v experimentaldomain.SaaSEditionProfile) domain.SaaSEditionProfile {
	return domain.SaaSEditionProfile{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Region: v.Region, AdminTenantID: v.AdminTenantID, IsolationModel: v.IsolationModel, Status: v.Status, ConfigHash: v.ConfigHash, Limitations: append([]string(nil), v.Limitations...), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

func MarketplaceCollectorLegacyRecord(v experimentaldomain.MarketplaceCollector) domain.MarketplaceCollector {
	return domain.MarketplaceCollector{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Provider: v.Provider, Version: v.Version, Publisher: v.Publisher, ManifestHash: v.ManifestHash, SignatureID: v.SignatureID, SBOMID: v.SBOMID, ScanID: v.ScanID, State: v.State, Limitations: append([]string(nil), v.Limitations...), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
