package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var _ packageapp.GraphSnapshotReader = futureExtensions{}

// Coordinate-only current ownership guards also run before cached replay.
func (r futureExtensions) ReadGraphSnapshotScope(ctx context.Context, tenant, product, release string) (packageapp.GraphSnapshotScope, error) {
	out := packageapp.GraphSnapshotScope{TenantID: tenant, ProductID: product, ReleaseID: release}
	kind, id := "product", product
	if release != "" {
		kind, id = "release", release
	}
	s, err := r.ReadEvidenceSummaryScope(ctx, tenant, kind, id)
	if err != nil {
		return out, err
	}
	if product != "" && product != s.Resources.ProductID {
		return out, app.ErrNotFound
	}
	out.Resources.ProductID, out.Resources.ReleaseID = s.Resources.ProductID, release
	return out, nil
}
func (r futureExtensions) ReadGraphSnapshotRoots(ctx context.Context, s packageapp.GraphSnapshotScope) ([]packagedomain.GraphNode, error) {
	out := []packagedomain.GraphNode{}
	for _, root := range []struct{ kind, id, query string }{
		{"product", s.ProductID, `SELECT left(name,65537),octet_length(name)>65536 FROM products WHERE tenant_id=$1 AND id=$2 FOR SHARE`},
		{"release", s.ReleaseID, `SELECT left(version,65537),octet_length(version)>65536 FROM releases WHERE tenant_id=$1 AND id=$2 FOR SHARE`},
	} {
		if root.id == "" {
			continue
		}
		var label string
		var oversized bool
		err := r.tx.QueryRow(ctx, root.query, s.TenantID, root.id).Scan(&label, &oversized)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, app.ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		if oversized {
			return nil, app.ErrValidation
		}
		out = append(out, packagedomain.GraphNode{ID: root.id, Type: root.kind, Label: label})
	}
	return out, nil
}

// Lock and size-check at most limit+1 selected rows before fetching titles or
// structured references. Payloads, source identities and arbitrary metadata
// are never selected. A limit overflow fails, rather than truncating the graph.
func (r futureExtensions) ReadGraphSnapshotEvidence(ctx context.Context, s packageapp.GraphSnapshotScope, limit int) ([]packageapp.GraphSnapshotEvidence, error) {
	if limit <= 0 || limit > packageapp.MaxEvidenceGraphNodes {
		return nil, app.ErrValidation
	}
	rows, err := r.tx.Query(ctx, `SELECT left(id,1025),octet_length(id),octet_length(title),left(coalesce(product_id,''),1025),left(coalesce(release_id,''),1025),
coalesce(octet_length(product_id)>1024,false) OR coalesce(octet_length(release_id)>1024,false),coalesce(octet_length(subject_refs::text),0),
CASE WHEN subject_refs IS NULL OR subject_refs='null'::jsonb THEN 0 WHEN jsonb_typeof(subject_refs)='array' THEN jsonb_array_length(subject_refs) ELSE -1 END
FROM evidence_items WHERE tenant_id=$1 AND ($2='' OR product_id=$2) AND ($3='' OR release_id=$3)
ORDER BY id COLLATE "C" LIMIT $4 FOR SHARE`, s.TenantID, s.ProductID, s.ReleaseID, limit+1)
	if err != nil {
		return nil, fmt.Errorf("preflight graph adjacency: %w", err)
	}
	defer rows.Close()
	items := []packageapp.GraphSnapshotEvidence{}
	total := 0
	for rows.Next() {
		var v packageapp.GraphSnapshotEvidence
		var idBytes, titleBytes, referenceBytes, referenceCount int
		var oversized bool
		if err := rows.Scan(&v.ID, &idBytes, &titleBytes, &v.ProductID, &v.ReleaseID, &oversized, &referenceBytes, &referenceCount); err != nil {
			return nil, err
		}
		if oversized || referenceCount < 0 {
			return nil, app.ErrConflict
		}
		if len(items) == limit || idBytes > packageapp.MaxGraphSnapshotIDBytes || titleBytes > packageapp.MaxGraphSnapshotLabelBytes || referenceCount > packageapp.MaxEvidenceGraphEdges {
			return nil, app.ErrValidation
		}
		total += idBytes + titleBytes + referenceBytes + len(v.ProductID) + len(v.ReleaseID)
		if total > packageapp.MaxGeneratedReportBytes {
			return nil, app.ErrValidation
		}
		v.TenantID = s.TenantID
		items = append(items, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if len(items) == 0 {
		return items, nil
	}
	ids := make([]string, len(items))
	releaseIDs := []string{}
	seen := map[string]bool{}
	for i, v := range items {
		ids[i] = v.ID
		if v.ProductID != "" && v.ProductID != s.Resources.ProductID {
			return nil, app.ErrNotFound
		}
		if v.ReleaseID != "" && !seen[v.ReleaseID] {
			seen[v.ReleaseID] = true
			releaseIDs = append(releaseIDs, v.ReleaseID)
		}
	}
	if len(releaseIDs) > 0 {
		parents, err := r.tx.Query(ctx, `SELECT id,left(product_id,1025),octet_length(product_id)>1024 FROM releases WHERE tenant_id=$1 AND id=ANY($2::text[]) ORDER BY id COLLATE "C" FOR SHARE`, s.TenantID, releaseIDs)
		if err != nil {
			return nil, err
		}
		count := 0
		for parents.Next() {
			var id, product string
			var oversized bool
			if err := parents.Scan(&id, &product, &oversized); err != nil {
				parents.Close()
				return nil, err
			}
			if oversized || product != s.Resources.ProductID {
				parents.Close()
				return nil, app.ErrNotFound
			}
			count++
		}
		err = parents.Err()
		parents.Close()
		if err != nil {
			return nil, err
		}
		if count != len(releaseIDs) {
			return nil, app.ErrNotFound
		}
	}
	metadata, err := r.tx.Query(ctx, `SELECT id,title,subject_refs FROM evidence_items WHERE tenant_id=$1 AND id=ANY($2::text[]) ORDER BY id COLLATE "C"`, s.TenantID, ids)
	if err != nil {
		return nil, err
	}
	defer metadata.Close()
	i := 0
	for metadata.Next() {
		var id string
		var raw json.RawMessage
		if i == len(items) {
			return nil, app.ErrConflict
		}
		if err := metadata.Scan(&id, &items[i].Title, &raw); err != nil {
			return nil, err
		}
		if id != items[i].ID {
			return nil, app.ErrConflict
		}
		var refs []struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &refs); err != nil {
				return nil, app.ErrConflict
			}
		}
		for _, ref := range refs {
			items[i].References = append(items[i].References, packageapp.GraphSnapshotReference{Type: ref.Type, ID: ref.ID})
		}
		i++
	}
	if err := metadata.Err(); err != nil {
		return nil, err
	}
	if i != len(items) {
		return nil, app.ErrConflict
	}
	return items, nil
}
func (r futureExtensions) InsertFocusedGraphSnapshot(ctx context.Context, v packagedomain.EvidenceGraphSnapshot) error {
	if v.ID == "" || v.TenantID == "" || v.GraphHash == "" || v.CreatedAt.IsZero() || v.SchemaVersion != packagedomain.EvidenceGraphSnapshotVersion || v.Nodes == nil || v.Edges == nil || len(v.Nodes) > packageapp.MaxEvidenceGraphNodes || len(v.Edges) > packageapp.MaxEvidenceGraphEdges {
		return app.ErrValidation
	}
	if _, err := r.ReadGraphSnapshotScope(ctx, v.TenantID, v.ProductID, v.ReleaseID); err != nil {
		return err
	}
	m := packageapp.GraphSnapshotHashMaterial(v)
	nodes, err := json.Marshal(m["nodes"])
	if err != nil {
		return err
	}
	edges, err := json.Marshal(m["edges"])
	if err != nil {
		return err
	}
	_, err = r.tx.Exec(ctx, `INSERT INTO evidence_graph_snapshots(id,tenant_id,product_id,release_id,nodes,edges,graph_hash,limitations,schema_version,created_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, v.ID, v.TenantID, nullableString(v.ProductID), nullableString(v.ReleaseID), nodes, edges, v.GraphHash, textArray(v.Limitations), v.SchemaVersion, v.CreatedAt)
	return writeError("insert graph snapshot", err)
}
