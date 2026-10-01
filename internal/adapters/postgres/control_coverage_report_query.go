package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	appquery "github.com/aatuh/evydence/internal/app/query"
	packagequery "github.com/aatuh/evydence/internal/package/query"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ packagequery.ControlCoverageReader = (*Store)(nil)

const (
	maxControlCoverageControlRowBytes   = 64 << 10
	maxControlCoverageLinkRowBytes      = 8 << 10
	maxControlCoverageExceptionRowBytes = 8 << 10
	maxControlCoverageSnapshotBytes     = 8 << 20
)

// ReadControlCoverageSnapshot returns a bounded report from one committed view.
// The shared control-evidence projection resolves each subject's current tenant,
// parent scope, and timestamp before a link can contribute to the report.
func (s *Store) ReadControlCoverageSnapshot(ctx context.Context, tenantID, frameworkID, productID, releaseID string, now time.Time) (packagequery.ControlCoverageSnapshot, error) {
	var empty packagequery.ControlCoverageSnapshot
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" || now.IsZero() {
		return empty, packagequery.ErrControlCoverageValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, fmt.Errorf("begin control coverage snapshot: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanupCtx)
	}()
	snapshot := packagequery.ControlCoverageSnapshot{TenantID: tenantID, ScopeReleaseID: releaseID}
	if productID != "" {
		err = tx.QueryRow(ctx, `SELECT id FROM products WHERE tenant_id=$1 AND id=$2`, tenantID, productID).Scan(&snapshot.ScopeProductID)
		if errors.Is(err, pgx.ErrNoRows) {
			return empty, packagequery.ErrControlCoverageNotFound
		}
		if err != nil {
			return empty, fmt.Errorf("resolve control coverage product: %w", err)
		}
	}
	if releaseID != "" {
		var releaseProduct string
		err = tx.QueryRow(ctx, `SELECT r.product_id FROM releases AS r JOIN products AS p ON p.id=r.product_id AND p.tenant_id=r.tenant_id WHERE r.tenant_id=$1 AND r.id=$2`, tenantID, releaseID).Scan(&releaseProduct)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && productID != "" && releaseProduct != productID {
			return empty, packagequery.ErrControlCoverageNotFound
		}
		if err != nil {
			return empty, fmt.Errorf("resolve control coverage release: %w", err)
		}
		snapshot.ScopeProductID = releaseProduct
	}
	if frameworkID == "" {
		err = tx.QueryRow(ctx, `SELECT id FROM control_frameworks WHERE tenant_id=$1 ORDER BY slug,version,id LIMIT 1`, tenantID).Scan(&snapshot.FrameworkID)
	} else {
		err = tx.QueryRow(ctx, `SELECT id FROM control_frameworks WHERE tenant_id=$1 AND id=$2`, tenantID, frameworkID).Scan(&snapshot.FrameworkID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, packagequery.ErrControlCoverageNotFound
	}
	if err != nil {
		return empty, fmt.Errorf("resolve control coverage framework: %w", err)
	}
	var oversized bool
	err = tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM security_controls AS c
		  WHERE c.tenant_id=$1 AND c.framework_id=$2 AND
		    octet_length(c.id)+octet_length(c.tenant_id)+octet_length(c.framework_id)+
		    octet_length(c.code)+octet_length(c.title)+octet_length(c.objective)+
		    octet_length(c.evidence_requirements::text)+octet_length(c.applicability::text)+
		    octet_length(c.limitations::text)+octet_length(c.schema_version)>$3)`,
		tenantID, snapshot.FrameworkID, maxControlCoverageControlRowBytes).Scan(&oversized)
	if err != nil {
		return empty, fmt.Errorf("bound control coverage controls: %w", err)
	}
	if oversized {
		return empty, packagequery.ErrControlCoverageCapacity
	}
	remaining := packagequery.MaxControlCoverageEntries
	remainingBytes := maxControlCoverageSnapshotBytes
	controls, err := tx.Query(ctx, `
		SELECT c.id,c.tenant_id,c.framework_id,c.code,c.title,c.objective,
		       c.evidence_requirements,c.applicability,c.limitations,c.schema_version,c.created_at
		FROM security_controls AS c
		WHERE c.tenant_id=$1 AND c.framework_id=$2
		ORDER BY c.code,c.id LIMIT $3`, tenantID, snapshot.FrameworkID, remaining+1)
	if err != nil {
		return empty, fmt.Errorf("read control coverage controls: %w", err)
	}
	for controls.Next() {
		var control riskdomain.SecurityControl
		var requirements, applicability, limitations []byte
		if err := controls.Scan(&control.ID, &control.TenantID, &control.FrameworkID, &control.Code, &control.Title, &control.Objective,
			&requirements, &applicability, &limitations, &control.SchemaVersion, &control.CreatedAt); err != nil {
			controls.Close()
			return empty, fmt.Errorf("scan control coverage control: %w", err)
		}
		if len(requirements) > maxStoredControlJSONBytes || len(applicability) > maxStoredControlJSONBytes || len(limitations) > maxStoredControlJSONBytes {
			controls.Close()
			return empty, packagequery.ErrControlCoverageProjection
		}
		control.EvidenceRequirements, err = decodeStoredControlRequirements(requirements)
		if err != nil || json.Unmarshal(applicability, &control.Applicability) != nil || json.Unmarshal(limitations, &control.Limitations) != nil {
			controls.Close()
			return empty, packagequery.ErrControlCoverageProjection
		}
		remainingBytes -= len(control.ID) + len(control.TenantID) + len(control.FrameworkID) + len(control.Code) + len(control.Title) + len(control.Objective) + len(requirements) + len(applicability) + len(limitations) + len(control.SchemaVersion)
		if remainingBytes < 0 {
			controls.Close()
			return empty, packagequery.ErrControlCoverageCapacity
		}
		snapshot.Controls = append(snapshot.Controls, control)
	}
	err = controls.Err()
	controls.Close()
	if err != nil {
		return empty, fmt.Errorf("iterate control coverage controls: %w", err)
	}
	if len(snapshot.Controls) > remaining {
		return empty, packagequery.ErrControlCoverageCapacity
	}
	remaining -= len(snapshot.Controls)
	err = tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM control_evidence AS l
		  JOIN security_controls AS c ON c.id=l.control_id AND c.tenant_id=l.tenant_id
		  WHERE l.tenant_id=$1 AND c.framework_id=$2
		    AND ($3::text='' OR l.product_id IS NULL OR l.product_id=$3)
		    AND ($4::text='' OR l.release_id IS NULL OR l.release_id=$4)
		    AND octet_length(l.id)+octet_length(l.tenant_id)+octet_length(l.control_id)+
		        octet_length(l.evidence_type)+octet_length(l.subject_type)+octet_length(l.subject_id)+
		        octet_length(COALESCE(l.product_id,''))+octet_length(COALESCE(l.release_id,''))+
		        octet_length(l.confidence)+octet_length(COALESCE(l.notes,''))+
		        octet_length(l.schema_version)>$5)`,
		tenantID, snapshot.FrameworkID, snapshot.ScopeProductID, releaseID, maxControlCoverageLinkRowBytes).Scan(&oversized)
	if err != nil {
		return empty, fmt.Errorf("bound control coverage links: %w", err)
	}
	if oversized {
		return empty, packagequery.ErrControlCoverageCapacity
	}
	for {
		pageSize := min(appquery.MaxPageSize, remaining+1)
		var after *appquery.SortKey
		if len(snapshot.Links) != 0 {
			last := snapshot.Links[len(snapshot.Links)-1].Link
			key := appquery.SortKey{ID: last.ID, Value: last.ID}
			after = &key
		}
		page, err := pageControlEvidence(ctx, tx, riskquery.ControlEvidencePageRequest{
			TenantID: tenantID, TenantWide: true,
			Page: appquery.PageRequest{PageSize: pageSize, Sort: appquery.SortID, Direction: appquery.Ascending}, After: after,
		}, snapshot.FrameworkID, snapshot.ScopeProductID, releaseID)
		if err != nil {
			return empty, fmt.Errorf("read scoped control coverage links: %w", err)
		}
		for _, point := range page.Items {
			link := point.Link
			remainingBytes -= len(link.ID) + len(link.TenantID) + len(link.ControlID) + len(link.EvidenceType) + len(link.SubjectType) + len(link.SubjectID) + len(link.ProductID) + len(link.ReleaseID) + len(link.Confidence) + len(link.Notes) + len(link.SchemaVersion)
			if remainingBytes < 0 {
				return empty, packagequery.ErrControlCoverageCapacity
			}
			snapshot.Links = append(snapshot.Links, packagequery.ControlCoverageLink{Link: point.Link, SubjectObservedAt: point.ObservedAt})
		}
		if len(snapshot.Links) > remaining {
			return empty, packagequery.ErrControlCoverageCapacity
		}
		if page.Next == nil {
			break
		}
	}
	remaining -= len(snapshot.Links)
	{
		err = tx.QueryRow(ctx, `
			SELECT EXISTS(SELECT 1 FROM exceptions AS x
			  JOIN releases AS r ON r.id=x.release_id AND r.tenant_id=x.tenant_id
			  JOIN products AS p ON p.id=r.product_id AND p.tenant_id=r.tenant_id
			  JOIN security_controls AS c ON c.id=x.control_id AND c.tenant_id=x.tenant_id AND c.framework_id=$2
			  WHERE x.tenant_id=$1 AND x.approved AND x.expires_at>$3
			    AND ($4::text='' OR p.id=$4) AND ($5::text='' OR r.id=$5)
			    AND octet_length(x.id)+octet_length(x.tenant_id)+octet_length(x.release_id)+
			        octet_length(COALESCE(x.finding_id,''))+octet_length(x.control_id)+
			        octet_length(x.reason)+octet_length(x.owner)+octet_length(COALESCE(x.approved_by,''))>$6)`,
			tenantID, snapshot.FrameworkID, now, snapshot.ScopeProductID, releaseID, maxControlCoverageExceptionRowBytes).Scan(&oversized)
		if err != nil {
			return empty, fmt.Errorf("bound control coverage exceptions: %w", err)
		}
		if oversized {
			return empty, packagequery.ErrControlCoverageCapacity
		}
		exceptions, err := tx.Query(ctx, `
			SELECT x.id,x.tenant_id,x.release_id,x.finding_id,x.control_id,x.reason,x.owner,
			       x.expires_at,x.approved,x.approved_by,x.approved_at,x.created_at
			FROM exceptions AS x
			JOIN releases AS r ON r.id=x.release_id AND r.tenant_id=x.tenant_id
			JOIN products AS p ON p.id=r.product_id AND p.tenant_id=r.tenant_id
			JOIN security_controls AS c ON c.id=x.control_id AND c.tenant_id=x.tenant_id AND c.framework_id=$2
			WHERE x.tenant_id=$1 AND x.approved AND x.expires_at>$3
			  AND ($4::text='' OR p.id=$4) AND ($5::text='' OR r.id=$5)
			ORDER BY x.id LIMIT $6`, tenantID, snapshot.FrameworkID, now, snapshot.ScopeProductID, releaseID, remaining+1)
		if err != nil {
			return empty, fmt.Errorf("read control coverage exceptions: %w", err)
		}
		for exceptions.Next() {
			var exception riskdomain.Exception
			var findingID, controlID, approvedBy sql.NullString
			var approvedAt sql.NullTime
			if err := exceptions.Scan(&exception.ID, &exception.TenantID, &exception.ReleaseID, &findingID, &controlID,
				&exception.Reason, &exception.Owner, &exception.ExpiresAt, &exception.Approved, &approvedBy, &approvedAt, &exception.CreatedAt); err != nil {
				exceptions.Close()
				return empty, fmt.Errorf("scan control coverage exception: %w", err)
			}
			exception.FindingID, exception.ControlID, exception.ApprovedBy, exception.ApprovedAt = nullableSQLString(findingID), nullableSQLString(controlID), nullableSQLString(approvedBy), nullableSQLTime(approvedAt)
			remainingBytes -= len(exception.ID) + len(exception.TenantID) + len(exception.ReleaseID) + len(exception.FindingID) + len(exception.ControlID) + len(exception.Reason) + len(exception.Owner) + len(exception.ApprovedBy)
			if remainingBytes < 0 {
				exceptions.Close()
				return empty, packagequery.ErrControlCoverageCapacity
			}
			snapshot.Exceptions = append(snapshot.Exceptions, exception)
		}
		err = exceptions.Err()
		exceptions.Close()
		if err != nil {
			return empty, fmt.Errorf("iterate control coverage exceptions: %w", err)
		}
		if len(snapshot.Exceptions) > remaining {
			return empty, packagequery.ErrControlCoverageCapacity
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit control coverage snapshot: %w", err)
	}
	return snapshot, nil
}
