CREATE TABLE IF NOT EXISTS incident_webhook_receivers (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    incident_id text NOT NULL,
    name text NOT NULL,
    provider text NOT NULL,
    public_key text NOT NULL,
    status text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_webhook_events (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    receiver_id text NOT NULL,
    incident_id text NOT NULL,
    provider text NOT NULL,
    event_id text NOT NULL,
    payload_hash text NOT NULL,
    signature_hash text NOT NULL,
    timeline_event_id text,
    result text NOT NULL,
    schema_version text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, receiver_id, event_id)
);

CREATE INDEX IF NOT EXISTS incident_webhook_receivers_tenant_incident_idx
    ON incident_webhook_receivers (tenant_id, incident_id, created_at);

CREATE INDEX IF NOT EXISTS incident_webhook_events_tenant_incident_idx
    ON incident_webhook_events (tenant_id, incident_id, created_at);
