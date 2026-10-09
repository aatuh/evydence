package postgres

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// This untrusted prefix lookup supplies coordinates only. The command acquires
// the tenant writer fence and rechecks the locked credential before any effect.
// Ambiguous prefixes fail closed; never scan all tenant credentials or hashes.
func (s *Store) LookupPortalAccess(ctx context.Context, prefix string) (packageapp.PortalAccessCandidate, error) {
	var empty packageapp.PortalAccessCandidate
	if s == nil || s.pool == nil || ctx == nil {
		return empty, packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if len(prefix) != 12 || !utf8.ValidString(prefix) || !strings.HasPrefix(prefix, "evycp_") || strings.ContainsRune(prefix, 0) {
		return empty, application.ErrUnauthorized
	}
	rows, err := s.pool.Query(ctx, `SELECT left(tenant_id,1025),left(id,1025),octet_length(tenant_id)>1024 OR octet_length(id)>1024 FROM customer_portal_access WHERE prefix=$1 ORDER BY tenant_id,id LIMIT 2`, prefix)
	if err != nil {
		return empty, fmt.Errorf("lookup portal credential coordinates: %w", err)
	}
	defer rows.Close()
	var v packageapp.PortalAccessCandidate
	count := 0
	for rows.Next() {
		var oversized bool
		count++
		if err := rows.Scan(&v.TenantID, &v.AccessID, &oversized); err != nil {
			return empty, err
		}
		if oversized {
			return empty, application.ErrUnauthorized
		}
	}
	if err := rows.Err(); err != nil {
		return empty, err
	}
	if count != 1 {
		return empty, application.ErrUnauthorized
	}
	return v, nil
}
