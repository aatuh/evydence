package query

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type metricsBoundaryReader struct {
	hook     func()
	calls    int
	tenant   string
	instance bool
}

func (r *metricsBoundaryReader) ReadMetricsSnapshot(_ context.Context, tenant string, instance bool) (MetricsSnapshot, error) {
	r.calls++
	r.tenant, r.instance = tenant, instance
	if r.hook != nil {
		r.hook()
	}
	counts := map[string]int{}
	for _, name := range metricResourceNames {
		counts[name] = 0
	}
	snapshot := MetricsSnapshot{ResourceCounts: counts}
	if instance {
		snapshot.Outbox = &OutboxCounts{}
	}
	return snapshot, nil
}

func TestMetricsWithholdCountsWhenOriginalAuthorityChangesDuringRead(t *testing.T) {
	for _, tc := range []struct {
		name     string
		actor    identitydomain.Actor
		instance bool
		revoke   func(identitydomain.Actor)
	}{
		{"tenant key", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin"}}, false, func(a identitydomain.Actor) { a.Scopes[0] = "revoked" }},
		{"tenant wildcard", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}, false, func(a identitydomain.Actor) { a.Scopes[0] = "revoked" }},
		{"current human grant", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}}, false, func(a identitydomain.Actor) { a.ResourceGrants[0].ResourceID = "foreign" }},
		{"current human grant capability", identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}}, false, func(a identitydomain.Actor) { a.ResourceGrants[0].Scopes[0] = "revoked" }},
		{"instance to tenant", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"instance:admin", "admin"}}, true, func(a identitydomain.Actor) { a.Scopes[0] = "revoked" }},
		{"tenant to instance", identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"admin"}}, false, func(a identitydomain.Actor) { a.Scopes[0] = "instance:admin" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &metricsBoundaryReader{}
			s, err := NewMetrics(reader, func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) })
			if err != nil {
				t.Fatal(err)
			}
			if result, err := s.Snapshot(t.Context(), tc.actor); err != nil || result == nil || reader.calls != 1 || reader.tenant != "tenant" || reader.instance != tc.instance {
				t.Fatal("authorized selected-view baseline", err, reader.calls, reader.tenant, reader.instance)
			}
			reader.hook = func() { tc.revoke(tc.actor) }
			if result, err := s.Snapshot(t.Context(), tc.actor); !errors.Is(err, authz.ErrForbidden) || result != nil || reader.calls != 2 || reader.instance != tc.instance {
				t.Fatal("changed authority returned original metrics", err, reader.calls, reader.instance)
			}
			if tc.name != "instance to tenant" && tc.name != "tenant to instance" {
				if result, err := s.Snapshot(t.Context(), tc.actor); !errors.Is(err, authz.ErrForbidden) || result != nil || reader.calls != 2 {
					t.Fatal("revoked authority reached storage", err, reader.calls)
				}
			}
		})
	}
}

func TestMetricsWithholdCountsAfterReaderCancellation(t *testing.T) {
	for _, scope := range []string{"admin", "instance:admin"} {
		t.Run(scope, func(t *testing.T) {
			reader := &metricsBoundaryReader{}
			s, err := NewMetrics(reader, func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) })
			if err != nil {
				t.Fatal(err)
			}
			actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{scope}}
			if result, err := s.Snapshot(t.Context(), actor); err != nil || result == nil || reader.calls != 1 {
				t.Fatal("authorized metrics baseline", err, reader.calls)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reader.hook = cancel
			if result, err := s.Snapshot(ctx, actor); !errors.Is(err, context.Canceled) || result != nil || reader.calls != 2 {
				t.Error("canceled metrics returned tenant/global counts", err, reader.calls)
			}
		})
	}
}
