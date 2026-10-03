CREATE INDEX IF NOT EXISTS collector_releases_health_latest_idx
    ON collector_releases (tenant_id, collector_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS collector_releases_health_pinned_idx
    ON collector_releases (tenant_id, collector_id, created_at DESC, id DESC)
    WHERE pinned = true;
