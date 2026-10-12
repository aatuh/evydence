-- A portal token resolves its owner through a bounded prefix point lookup.
-- Prefix collisions are allowed for compatibility and fail closed at lookup.
CREATE INDEX IF NOT EXISTS customer_portal_access_prefix_lookup_idx
    ON customer_portal_access (prefix, tenant_id, id);
