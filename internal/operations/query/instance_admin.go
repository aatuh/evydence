package query

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

// InstanceCounts contains only global cardinalities. It carries no tenant
// identifiers, raw evidence, credentials, or diagnostic error strings.
type InstanceCounts struct {
	Tenants    int
	Users      int
	Collectors int
	Evidence   int
}

type InstanceCountsReader interface {
	ReadInstanceCounts(context.Context) (InstanceCounts, error)
}

type InstanceAdmin struct {
	reader InstanceCountsReader
	now    func() time.Time
}

func NewInstanceAdmin(reader InstanceCountsReader, now func() time.Time) (*InstanceAdmin, error) {
	if reader == nil || now == nil {
		return nil, ErrValidation
	}
	return &InstanceAdmin{reader: reader, now: now}, nil
}

func (s *InstanceAdmin) Snapshot(ctx context.Context, actor identitydomain.Actor) (operationsdomain.InstanceAdminSnapshot, error) {
	var empty operationsdomain.InstanceAdminSnapshot
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := application.AuthorizeInstanceScope(ctx, actor, "instance:admin"); err != nil {
		return empty, err
	}
	counts, err := s.reader.ReadInstanceCounts(ctx)
	if err != nil {
		return empty, err
	}
	if counts.Tenants < 0 || counts.Users < 0 || counts.Collectors < 0 || counts.Evidence < 0 {
		return empty, ErrInvalidProjection
	}
	return operationsdomain.InstanceAdminSnapshot{
		ReportType: "instance_admin_snapshot", TenantCount: counts.Tenants,
		ResourceCounts: map[string]int{"tenants": counts.Tenants, "users": counts.Users, "collectors": counts.Collectors, "evidence": counts.Evidence},
		Limitations:    []string{"Instance admin diagnostics expose operational counts only and not raw evidence payloads or secrets."},
		GeneratedAt:    s.now(),
	}, nil
}
