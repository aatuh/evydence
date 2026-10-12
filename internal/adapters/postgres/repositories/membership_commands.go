package repositories

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var _ identityapp.MembershipWriteReader = identity{}

func (r identity) LockMembershipWrites(ctx context.Context, tenant string) error {
	// Same worker-projection fence followed by the tenant row, not a Go mutex.
	return r.LockAPIKeyCreation(ctx, tenant)
}
func validMembershipQueryText(value string, max int) bool {
	return value != "" && len(value) <= max && utf8.ValidString(value) && !strings.ContainsRune(value, 0) && strings.TrimSpace(value) == value
}
func (r identity) OrganizationSlugExists(ctx context.Context, tenant, slug string) (bool, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(slug, identityapp.MaxMembershipKeyBytes) || len(tenant)+len(slug) > identityapp.MaxMembershipKeyBytes {
		return false, app.ErrValidation
	}
	var found bool
	err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE tenant_id=$1 AND slug=$2)`, tenant, slug).Scan(&found)
	return found, writeError("read organization identity", err)
}
func (r identity) UserEmailExists(ctx context.Context, tenant, email string) (bool, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(email, identityapp.MaxMembershipKeyBytes) || len(tenant)+len(email) > identityapp.MaxMembershipKeyBytes {
		return false, app.ErrValidation
	}
	var found bool
	err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM human_users WHERE tenant_id=$1 AND email=$2)`, tenant, email).Scan(&found)
	return found, writeError("read user identity", err)
}
func (r identity) ReadMembershipOrganization(ctx context.Context, tenant, id string) (identityapp.MembershipOrganization, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(id, 1024) {
		return identityapp.MembershipOrganization{}, app.ErrValidation
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM organizations WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id); err != nil {
		return identityapp.MembershipOrganization{}, err
	}
	return identityapp.MembershipOrganization{ID: id, TenantID: tenant}, nil
}
func (r identity) ReadMembershipUser(ctx context.Context, tenant, id string) (identitydomain.HumanUser, error) {
	if ctx == nil || r.tx == nil || !validMembershipQueryText(tenant, 1024) || !validMembershipQueryText(id, 1024) {
		return identitydomain.HumanUser{}, app.ErrValidation
	}
	// Bound each selected field before transfer. Excess historical metadata is
	// a conflict, never a silently truncated public response. No inventory,
	// provider trust material, role bindings or session credentials are read.
	user := identitydomain.HumanUser{ID: id, TenantID: tenant}
	var deactivated sql.NullTime
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT left(coalesce(organization_id,''),1025),left(email,2305),left(display_name,65537),left(status,129),left(schema_version,1025),created_at,deactivated_at,
		coalesce(octet_length(organization_id),0)>1024 OR octet_length(email)>2304 OR octet_length(display_name)>65536 OR octet_length(status)>128 OR octet_length(schema_version)>1024
		FROM human_users WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&user.OrganizationID, &user.Email, &user.DisplayName, &user.Status, &user.SchemaVersion, &user.CreatedAt, &deactivated, &oversized)
	if errors.Is(err, pgx.ErrNoRows) {
		return identitydomain.HumanUser{}, app.ErrNotFound
	}
	if err != nil {
		return identitydomain.HumanUser{}, writeError("read user lifecycle", err)
	}
	if oversized {
		return identitydomain.HumanUser{}, app.ErrConflict
	}
	user.CreatedAt = user.CreatedAt.UTC()
	if deactivated.Valid {
		v := deactivated.Time.UTC()
		user.DeactivatedAt = &v
	}
	return user, nil
}
