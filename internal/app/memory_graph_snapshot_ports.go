package app

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/aatuh/evydence/internal/application"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func memoryGraphScope(state *MemoryUnitOfWorkSnapshot, tenant, product, release string) (packageapp.GraphSnapshotScope, error) {
	if product == "" && release == "" {
		return packageapp.GraphSnapshotScope{}, ErrValidation
	}
	s, err := memoryAnswerLibraryScope(state, tenant, product, release)
	return packageapp.GraphSnapshotScope{TenantID: tenant, ProductID: product, ReleaseID: release, Resources: s.Resources}, err
}
func (r memoryFutureExtensionsRepository) ReadGraphSnapshotScope(ctx context.Context, tenant, product, release string) (packageapp.GraphSnapshotScope, error) {
	var out packageapp.GraphSnapshotScope
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryGraphScope(state, tenant, product, release)
		return err
	})
	return out, err
}
func memoryCurrentGraphScope(state *MemoryUnitOfWorkSnapshot, s packageapp.GraphSnapshotScope) error {
	current, err := memoryGraphScope(state, s.TenantID, s.ProductID, s.ReleaseID)
	if err != nil {
		return err
	}
	if current != s {
		return ErrConflict
	}
	return nil
}
func (r memoryFutureExtensionsRepository) ReadGraphSnapshotRoots(ctx context.Context, s packageapp.GraphSnapshotScope) ([]packagedomain.GraphNode, error) {
	var out []packagedomain.GraphNode
	err := memoryIdentityRepository(r).membershipRead(ctx, s.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := memoryCurrentGraphScope(state, s); err != nil {
			return err
		}
		out = []packagedomain.GraphNode{}
		for _, root := range []struct{ id, kind, label string }{{s.ProductID, "product", state.Products[s.ProductID].Name}, {s.ReleaseID, "release", state.Releases[s.ReleaseID].Version}} {
			if root.id == "" {
				continue
			}
			if !memoryMembershipText(root.label, packageapp.MaxGraphSnapshotLabelBytes) {
				return ErrValidation
			}
			out = append(out, packagedomain.GraphNode{ID: root.id, Type: root.kind, Label: root.label})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r memoryFutureExtensionsRepository) ReadGraphSnapshotEvidence(ctx context.Context, s packageapp.GraphSnapshotScope, limit int) ([]packageapp.GraphSnapshotEvidence, error) {
	if limit <= 0 || limit > packageapp.MaxEvidenceGraphNodes {
		return nil, ErrValidation
	}
	var out []packageapp.GraphSnapshotEvidence
	err := memoryIdentityRepository(r).membershipRead(ctx, s.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		if err := memoryCurrentGraphScope(state, s); err != nil {
			return err
		}
		out = []packageapp.GraphSnapshotEvidence{}
		total := 0
		for key, e := range state.Evidence {
			if e.TenantID != s.TenantID || s.ProductID != "" && e.ProductID != s.ProductID || s.ReleaseID != "" && e.ReleaseID != s.ReleaseID {
				continue
			}
			if len(out) == limit || !memoryMembershipQueryText(e.ID, packageapp.MaxGraphSnapshotIDBytes) || !memoryMembershipText(e.Title, packageapp.MaxGraphSnapshotLabelBytes) || len(e.SubjectRefs) > packageapp.MaxEvidenceGraphEdges {
				return ErrValidation
			}
			if key != e.ID || !memoryMembershipText(e.ProductID, packageapp.MaxGraphSnapshotIDBytes) || !memoryMembershipText(e.ReleaseID, packageapp.MaxGraphSnapshotIDBytes) {
				return ErrConflict
			}
			parent, err := memoryAnswerLibraryScope(state, s.TenantID, e.ProductID, e.ReleaseID)
			if err != nil || parent.Resources.ProductID != s.Resources.ProductID {
				return ErrNotFound
			}
			base := len(e.ID) + len(e.Title) + len(e.ProductID) + len(e.ReleaseID)
			bytes := base
			for _, ref := range e.SubjectRefs {
				if !memoryMembershipText(ref.Type, packageapp.MaxGraphSnapshotReferenceTypeBytes) || !memoryMembershipText(ref.ID, packageapp.MaxGraphSnapshotIDBytes) {
					return ErrValidation
				}
				bytes += len(ref.Type) + len(ref.ID)
				if total+bytes > packageapp.MaxGeneratedReportBytes {
					return ErrValidation
				}
			}
			raw, err := json.Marshal(e.SubjectRefs)
			if err != nil || total+base+len(raw) > packageapp.MaxGeneratedReportBytes {
				return ErrValidation
			}
			total += base + len(raw)
			v := packageapp.GraphSnapshotEvidence{ID: e.ID, TenantID: e.TenantID, ProductID: e.ProductID, ReleaseID: e.ReleaseID, Title: e.Title}
			for _, ref := range e.SubjectRefs {
				v.References = append(v.References, packageapp.GraphSnapshotReference{Type: ref.Type, ID: ref.ID})
			}
			out = append(out, v)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r memoryFutureExtensionsRepository) InsertFocusedGraphSnapshot(ctx context.Context, v packagedomain.EvidenceGraphSnapshot) error {
	if !memoryMembershipQueryText(v.ID, packageapp.MaxGraphSnapshotIDBytes) || v.Nodes == nil || v.Edges == nil || len(v.Nodes) > packageapp.MaxEvidenceGraphNodes || len(v.Edges) > packageapp.MaxEvidenceGraphEdges ||
		len(v.Limitations) > packageapp.MaxEvidenceGraphNodes || v.SchemaVersion != packagedomain.EvidenceGraphSnapshotVersion || v.CreatedAt.IsZero() {
		return ErrValidation
	}
	if _, err := r.ReadGraphSnapshotScope(ctx, v.TenantID, v.ProductID, v.ReleaseID); err != nil {
		return err
	}
	total := 0
	check := func(values ...string) bool {
		for _, value := range values {
			if !memoryMembershipText(value, packageapp.MaxGraphSnapshotLabelBytes) {
				return false
			}
			total += len(value)
		}
		return total <= packageapp.MaxGeneratedReportBytes
	}
	for _, n := range v.Nodes {
		if !check(n.ID, n.Type, n.Label) {
			return ErrValidation
		}
	}
	for _, e := range v.Edges {
		if !check(e.From, e.To, e.Relationship) {
			return ErrValidation
		}
	}
	for _, value := range v.Limitations {
		if !check(value) {
			return ErrValidation
		}
	}
	hash, err := application.NormalizedJSONHash(packageapp.GraphSnapshotHashMaterial(v))
	if err != nil || hash != v.GraphHash {
		return ErrValidation
	}
	raw, err := packageapp.EncodeGraphSnapshot(v)
	if err != nil || len(raw) > packageapp.MaxGeneratedReportBytes {
		return ErrValidation
	}
	return r.InsertEvidenceGraphSnapshot(ctx, graphSnapshotLegacyRecord(v))
}

var _ packageapp.GraphSnapshotReader = memoryFutureExtensionsRepository{}
