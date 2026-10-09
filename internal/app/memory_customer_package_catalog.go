package app

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

// A private component of the complete focused fixture snapshot. The caller
// must hold one typed transaction view for all components. Memory scans do not
// establish PostgreSQL query, transfer, locking or durability guarantees.
type memoryCustomerPackageCatalog struct {
	Tenant, Organization, Product, Release map[string]any
	Evidence                               []packageapp.EvidenceReference
	Artifacts                              []map[string]any
}

type memoryCustomerSnapshotBudget struct{ remainingBytes int }

func memoryCustomerSnapshotID(id string, optional bool) bool {
	return (optional || id != "") && strings.TrimSpace(id) == id && memoryGovernanceText(id, packageapp.MaxCustomerPackageIDBytes)
}

func memoryCustomerSnapshotTime(at time.Time) (string, error) {
	at = at.UTC()
	if at.Year() < 1 || at.Year() > 9999 {
		return "", ErrConflict
	}
	return at.Format(time.RFC3339), nil
}

// Check scalar/tree bounds before JSON allocation. The exact encoded size is
// charged afterward; a section never receives a fresh independent byte limit.
func memoryCustomerMetadataFits(value any, remaining *int, depth int) bool {
	if depth > 32 || *remaining < 0 {
		return false
	}
	text := func(s string) bool {
		if !memoryGovernanceText(s, *remaining) {
			return false
		}
		*remaining -= len(s)
		return true
	}
	switch v := value.(type) {
	case string:
		return text(v)
	case map[string]any:
		if len(v) > 4096 {
			return false
		}
		for k, child := range v {
			if !text(k) || !memoryCustomerMetadataFits(child, remaining, depth+1) {
				return false
			}
		}
	case map[string]int:
		if len(v) > 4096 {
			return false
		}
		for k, count := range v {
			if count < 0 || !text(k) {
				return false
			}
		}
	case []map[string]any:
		if len(v) > packageapp.MaxSecurityReviewEvidenceIDs {
			return false
		}
		for _, child := range v {
			if !memoryCustomerMetadataFits(child, remaining, depth+1) {
				return false
			}
		}
	case []string:
		if len(v) > packageapp.MaxSecurityReviewEvidenceIDs {
			return false
		}
		for _, child := range v {
			if !text(child) {
				return false
			}
		}
	case []any:
		if len(v) > 4096 {
			return false
		}
		for _, child := range v {
			if !memoryCustomerMetadataFits(child, remaining, depth+1) {
				return false
			}
		}
	case json.Number:
		return text(v.String())
	case nil, bool, int, int64, float64:
	default:
		return false
	}
	return true
}

func (b *memoryCustomerSnapshotBudget) charge(value any) error {
	remaining := b.remainingBytes
	if !memoryCustomerMetadataFits(value, &remaining, 0) {
		return ErrConflict
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return ErrConflict
	}
	return b.chargeJSON(raw)
}

func (b *memoryCustomerSnapshotBudget) chargeJSON(raw []byte) error {
	if len(raw) > b.remainingBytes || jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 32, MaxObjectKeys: 4096, MaxArrayItems: packageapp.MaxSecurityReviewEvidenceIDs, MaxStringBytes: packageapp.MaxCustomerPackageManifestBytes}) != nil {
		return ErrConflict
	}
	b.remainingBytes -= len(raw)
	return nil
}

func memoryCustomerEvidenceInScope(s *MemoryUnitOfWorkSnapshot, key string, e domain.EvidenceItem, tenant, product, release string) bool {
	if e.ID != key || e.TenantID != tenant || release != "" && e.ReleaseID != release {
		return false
	}
	refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID, BuildID: e.BuildID, DeploymentID: e.DeploymentID})
	return err == nil && refs.ProductID == product
}

func memoryCustomerBuildInScope(s *MemoryUnitOfWorkSnapshot, key string, b domain.BuildRun, tenant, product, release string) bool {
	if release == "" || b.ID != key || b.TenantID != tenant || b.ReleaseID != release || b.ProjectID == "" {
		return false
	}
	refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{BuildID: b.ID})
	return err == nil && refs.ProductID == product && refs.ReleaseID == release
}

func readMemoryCustomerPackageCatalog(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, budget *memoryCustomerSnapshotBudget) (memoryCustomerPackageCatalog, error) {
	var empty memoryCustomerPackageCatalog
	if err := validateMemoryCustomerSnapshotRead(ctx, s, tenant, product, release, budget); err != nil {
		return empty, err
	}
	t := s.Tenants[tenant]
	working := *budget
	p := s.Products[product]
	created, err := memoryCustomerSnapshotTime(p.CreatedAt)
	if err != nil {
		return empty, err
	}
	out := memoryCustomerPackageCatalog{
		Tenant: map[string]any{"id": t.ID, "name": t.Name}, Product: map[string]any{"id": p.ID, "name": p.Name, "slug": p.Slug, "created_at": created},
		Release: map[string]any{}, Evidence: []packageapp.EvidenceReference{}, Artifacts: []map[string]any{},
	}
	if err := working.charge(map[string]any{"tenant": out.Tenant, "product": out.Product}); err != nil {
		return empty, err
	}
	if release != "" {
		r := s.Releases[release]
		created, err := memoryCustomerSnapshotTime(r.CreatedAt)
		if err != nil {
			return empty, err
		}
		out.Release = map[string]any{"id": r.ID, "product_id": r.ProductID, "version": r.Version, "state": string(r.State), "created_at": created}
		for _, at := range []struct {
			key string
			at  *time.Time
		}{{"frozen_at", r.FrozenAt}, {"approved_at", r.ApprovedAt}} {
			if at.at != nil {
				text, err := memoryCustomerSnapshotTime(*at.at)
				if err != nil {
					return empty, err
				}
				out.Release[at.key] = text
			}
		}
		if err := working.charge(out.Release); err != nil {
			return empty, err
		}
	}
	organizations := []map[string]any{}
	for id, o := range s.Organizations {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if o.TenantID != tenant || o.ID != id {
			continue
		}
		if !memoryCustomerSnapshotID(id, false) || len(organizations) == packageapp.MaxSecurityReviewEvidenceIDs {
			return empty, ErrConflict
		}
		created, err := memoryCustomerSnapshotTime(o.CreatedAt)
		if err != nil {
			return empty, err
		}
		row := map[string]any{"id": id, "name": o.Name, "slug": o.Slug, "status": o.Status, "created": created}
		if err := working.charge(row); err != nil {
			return empty, err
		}
		organizations = append(organizations, row)
	}
	sortMemoryCustomerMetadata(organizations)
	out.Organization = map[string]any{"records": organizations, "limitations": []string{"Organization records are included only as tenant metadata; product-to-organization ownership is not inferred by this package schema."}}
	selected := make(map[string]bool)
	for id, e := range s.Evidence {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if !memoryCustomerEvidenceInScope(s, id, e, tenant, product, release) {
			continue
		}
		if !memoryCustomerSnapshotID(id, false) || !memoryCustomerSnapshotID(e.Type, false) || len(out.Evidence) == packageapp.MaxSecurityReviewEvidenceIDs {
			return empty, ErrConflict
		}
		if err := working.charge(map[string]any{"id": id, "type": e.Type}); err != nil {
			return empty, err
		}
		out.Evidence = append(out.Evidence, packageapp.EvidenceReference{ID: id, Type: e.Type})
		selected[id] = true
	}
	sort.Slice(out.Evidence, func(i, j int) bool { return out.Evidence[i].ID < out.Evidence[j].ID })
	if release != "" {
		out.Artifacts, err = readMemoryCustomerCatalogArtifacts(ctx, s, tenant, product, release, selected, &working)
		if err != nil {
			return empty, err
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	*budget = working
	return out, nil
}

func validateMemoryCustomerSnapshotRead(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, budget *memoryCustomerSnapshotBudget) error {
	if ctx == nil || s == nil || budget == nil || budget.remainingBytes < 0 || budget.remainingBytes > packageapp.MaxCustomerPackageManifestBytes || !memoryCustomerSnapshotID(tenant, false) || !memoryCustomerSnapshotID(product, false) || !memoryCustomerSnapshotID(release, true) {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t, ok := s.Tenants[tenant]
	if !ok || t.ID != tenant {
		return ErrNotFound
	}
	if _, err := memoryGovernanceProductRelease(s, tenant, product, release); err != nil {
		return err
	}
	return nil
}

// Association bounds are independent of the public metadata budget, matching
// the native catalog's capped input work. Payload/metadata fields are unread.
func memoryCustomerCatalogArtifactIDs(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, selected map[string]bool) (map[string]bool, error) {
	count, bytesRemaining := 0, packageapp.MaxCustomerPackageManifestBytes
	artifacts := make(map[string]bool)
	addArtifact := func(id string) error {
		a, owned := s.Artifacts[id]
		if id == "" || !owned || a.ID != id || a.TenantID != tenant {
			return nil
		}
		if !memoryCustomerSnapshotID(id, false) || !artifacts[id] && len(artifacts) == packageapp.MaxSecurityReviewEvidenceIDs {
			return ErrConflict
		}
		artifacts[id] = true
		return nil
	}
	charge := func(value any, elements int) error {
		if elements > packageapp.MaxSecurityReviewEvidenceIDs-count {
			return ErrConflict
		}
		raw, err := json.Marshal(value)
		if err != nil || len(raw) > bytesRemaining {
			return ErrConflict
		}
		count += elements
		bytesRemaining -= len(raw)
		return nil
	}
	for id := range selected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		refs := s.Evidence[id].SubjectRefs
		if len(refs) > packageapp.MaxSecurityReviewEvidenceIDs-count {
			return nil, ErrConflict
		}
		textRemaining := bytesRemaining
		for _, ref := range refs {
			for _, text := range []string{ref.Type, ref.ID, ref.Digest} {
				if !memoryGovernanceText(text, textRemaining) {
					return nil, ErrConflict
				}
				textRemaining -= len(text)
			}
			if ref.Type == "artifact" && ref.ID != "" {
				if err := addArtifact(ref.ID); err != nil {
					return nil, err
				}
			}
		}
		if err := charge(refs, len(refs)); err != nil {
			return nil, err
		}
	}
	for key, d := range s.SBOMs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if d.ID == key && d.TenantID == tenant && d.ReleaseID == release && selected[d.EvidenceID] && d.ArtifactID != "" {
			if err := addArtifact(d.ArtifactID); err != nil {
				return nil, err
			}
		}
	}
	for key, d := range s.VEXDocuments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if d.ID == key && d.TenantID == tenant && d.ReleaseID == release && selected[d.EvidenceID] && d.ArtifactID != "" {
			if err := addArtifact(d.ArtifactID); err != nil {
				return nil, err
			}
		}
	}
	buildCount := 0
	for key, b := range s.BuildRuns {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !memoryCustomerBuildInScope(s, key, b, tenant, product, release) {
			continue
		}
		buildCount++
		if buildCount > packageapp.MaxSecurityReviewEvidenceIDs || len(b.Outputs) > packageapp.MaxSecurityReviewEvidenceIDs-count {
			return nil, ErrConflict
		}
		textRemaining := bytesRemaining
		for _, output := range b.Outputs {
			if !memoryGovernanceText(output.ArtifactID, textRemaining) || !memoryGovernanceText(output.Digest, textRemaining-len(output.ArtifactID)) {
				return nil, ErrConflict
			}
			textRemaining -= len(output.ArtifactID) + len(output.Digest)
			a, ok := s.Artifacts[output.ArtifactID]
			if ok && a.ID == output.ArtifactID && a.TenantID == tenant && a.Digest == output.Digest {
				if err := addArtifact(a.ID); err != nil {
					return nil, err
				}
			}
		}
		if err := charge(b.Outputs, len(b.Outputs)); err != nil {
			return nil, err
		}
	}
	return artifacts, nil
}

func readMemoryCustomerCatalogArtifacts(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, selected map[string]bool, budget *memoryCustomerSnapshotBudget) ([]map[string]any, error) {
	artifacts, err := memoryCustomerCatalogArtifactIDs(ctx, s, tenant, product, release, selected)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for id, a := range s.Artifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !artifacts[id] || a.ID != id || a.TenantID != tenant {
			continue
		}
		if !memoryCustomerSnapshotID(id, false) || a.Size < 0 || len(out) == packageapp.MaxSecurityReviewEvidenceIDs {
			return nil, ErrConflict
		}
		created, err := memoryCustomerSnapshotTime(a.CreatedAt)
		if err != nil {
			return nil, err
		}
		row := map[string]any{"id": id, "name": a.Name, "media_type": a.MediaType, "size": a.Size, "digest": a.Digest, "created_at": created}
		if err := budget.charge(row); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	sortMemoryCustomerMetadata(out)
	return out, nil
}

func sortMemoryCustomerMetadata(rows []map[string]any) {
	sort.Slice(rows, func(i, j int) bool { return rows[i]["id"].(string) < rows[j]["id"].(string) })
}
