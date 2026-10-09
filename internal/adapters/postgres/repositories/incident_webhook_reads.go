package repositories

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

var _ operationsapp.IncidentWebhookRouting = risk{}
var _ operationsapp.IncidentWebhookReader = risk{}

// This unauthenticated primary-key lookup returns only the tenant locator.
// Provider authentication follows a tenant-filtered, locked receiver re-read.
func (r risk) LookupIncidentWebhookTenant(ctx context.Context, id string) (string, error) {
	if err := validBuildIdentityRead(ctx, r.tx, "receiver-routing", id); err != nil {
		return "", err
	}
	if strings.TrimSpace(id) != id {
		return "", app.ErrValidation
	}
	var tenant string
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT left(tenant_id,1025),octet_length(tenant_id)>1024 FROM incident_webhook_receivers WHERE id=$1`, id).Scan(&tenant, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", app.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("locate incident webhook tenant: %w", err)
	}
	if oversized {
		return "", app.ErrValidation
	}
	return tenant, nil
}
func (r risk) ReadIncidentWebhookReceiver(ctx context.Context, tenant, id string) (operationsdomain.IncidentWebhookReceiver, error) {
	var v operationsdomain.IncidentWebhookReceiver
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return v, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return v, err
	}
	var oversized bool
	// Names and other documents are deliberately not selected. Each authority
	// field is bounded before crossing the storage/application boundary.
	err := r.tx.QueryRow(ctx, `SELECT left(incident_id,1025),left(provider,65537),left(public_key,1025),left(status,129),octet_length(incident_id)>1024 OR octet_length(provider)>65536 OR octet_length(public_key)>1024 OR octet_length(status)>128 FROM incident_webhook_receivers WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&v.IncidentID, &v.Provider, &v.PublicKey, &v.Status, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, app.ErrNotFound
	}
	if err != nil {
		return v, fmt.Errorf("read incident webhook authority: %w", err)
	}
	if oversized {
		return operationsdomain.IncidentWebhookReceiver{}, app.ErrValidation
	}
	v.ID, v.TenantID = id, tenant
	return v, nil
}
func (r risk) ReadIncidentWebhookReplay(ctx context.Context, tenant, receiver, event string) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	var v operationsdomain.IncidentWebhookEvent
	var e operationsdomain.IncidentTimelineEvent
	if err := validBuildIdentityRead(ctx, r.tx, tenant, receiver); err != nil {
		return v, e, err
	}
	if err := validBuildIdentityRead(ctx, r.tx, tenant, event); err != nil {
		return v, e, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return v, e, err
	}
	var oversized bool
	// The unique (tenant,receiver,event) key selects at most one receipt.
	err := r.tx.QueryRow(ctx, `SELECT left(id,1025),left(incident_id,1025),left(provider,65537),left(payload_hash,72),left(signature_hash,72),left(COALESCE(timeline_event_id,''),1025),left(result,129),left(schema_version,1025),created_at,octet_length(id)>1024 OR octet_length(incident_id)>1024 OR octet_length(provider)>65536 OR octet_length(payload_hash)>71 OR octet_length(signature_hash)>71 OR octet_length(COALESCE(timeline_event_id,''))>1024 OR octet_length(result)>128 OR octet_length(schema_version)>1024 FROM incident_webhook_events WHERE tenant_id=$1 AND receiver_id=$2 AND event_id=$3 FOR SHARE`, tenant, receiver, event).Scan(&v.ID, &v.IncidentID, &v.Provider, &v.PayloadHash, &v.SignatureHash, &v.TimelineEventID, &v.Result, &v.SchemaVersion, &v.CreatedAt, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, e, app.ErrNotFound
	}
	if err != nil {
		return v, e, fmt.Errorf("read incident webhook replay: %w", err)
	}
	if oversized {
		return v, e, app.ErrConflict
	}
	v.TenantID, v.ReceiverID, v.EventID = tenant, receiver, event
	err = r.tx.QueryRow(ctx, `SELECT left(incident_id,1025),left(event_type,2097153),left(summary,2097153),left(COALESCE(evidence_id,''),1025),occurred_at,left(schema_version,1025),created_at,octet_length(incident_id)>1024 OR octet_length(event_type)>2097152 OR octet_length(summary)>2097152 OR octet_length(COALESCE(evidence_id,''))>1024 OR octet_length(schema_version)>1024 FROM incident_timeline_events WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, v.TimelineEventID).Scan(&e.IncidentID, &e.EventType, &e.Summary, &e.EvidenceID, &e.OccurredAt, &e.SchemaVersion, &e.CreatedAt, &oversized)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && oversized {
		return v, e, app.ErrConflict
	}
	if err != nil {
		return v, e, fmt.Errorf("read incident webhook replay timeline: %w", err)
	}
	e.ID, e.TenantID = v.TimelineEventID, tenant
	v.CreatedAt = v.CreatedAt.UTC()
	e.CreatedAt, e.OccurredAt = e.CreatedAt.UTC(), e.OccurredAt.UTC()
	return v, e, nil
}
