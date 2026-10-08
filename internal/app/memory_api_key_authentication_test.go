package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestMemoryAPIKeyAuthenticationReadsBoundedCurrentCandidatesAndCollectorIdentity(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Identity.(interface {
		APIKeysByPrefix(context.Context, string) ([]identitydomain.APIKey, error)
		CollectorByAPIKey(context.Context, string, string) (identityapp.CollectorBinding, bool, error)
	})
	if !ok {
		t.Fatal("memory identity lacks native API-key authentication projections")
	}
	at := fixedNow()
	expires := at.Add(time.Hour)
	key := domain.APIKey{ID: "key", TenantID: "tenant", Name: "Collector", Prefix: "evy_test1234", Hash: strings.Repeat("a", 64), Scopes: []string{"evidence:write"}, ExpiresAt: &expires, CreatedAt: at}
	tx.state.APIKeys[key.ID] = key
	tx.state.Collectors["collector"] = domain.Collector{ID: "collector", TenantID: "tenant", APIKeyID: key.ID, Name: strings.Repeat("unselected-private", 10000)}
	tx.state.Collectors["foreign"] = domain.Collector{ID: "foreign", TenantID: "foreign", APIKeyID: key.ID}
	got, err := r.APIKeysByPrefix(t.Context(), key.Prefix)
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], identitydomain.APIKey(key)) {
		t.Fatal("candidate read lost complete metadata", got, err)
	}
	got[0].Scopes[0] = "mutated"
	*got[0].ExpiresAt = expires.Add(time.Hour)
	if tx.state.APIKeys[key.ID].Scopes[0] != "evidence:write" || !tx.state.APIKeys[key.ID].ExpiresAt.Equal(expires) {
		t.Fatal("candidate projection aliases mutable state")
	}
	binding, found, err := r.CollectorByAPIKey(t.Context(), "tenant", key.ID)
	if err != nil || !found || binding != (identityapp.CollectorBinding{ID: "collector", TenantID: "tenant", APIKeyID: key.ID}) {
		t.Fatal("collector lookup leaked foreign or unrelated metadata", binding, found, err)
	}
	tx.state.Collectors["ambiguous"] = domain.Collector{ID: "ambiguous", TenantID: "tenant", APIKeyID: key.ID}
	if v, found, err := r.CollectorByAPIKey(t.Context(), "tenant", key.ID); !errors.Is(err, ErrConflict) || found || v != (identityapp.CollectorBinding{}) {
		t.Fatal("ambiguous collector returned a partial identity", v, found, err)
	}
	key.Scopes = make([]string, 257)
	tx.state.APIKeys[key.ID] = key
	if v, err := r.APIKeysByPrefix(t.Context(), key.Prefix); !errors.Is(err, ErrConflict) || v != nil {
		t.Fatal("oversized scopes were truncated or returned", len(v), err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.APIKeysByPrefix(ctx, key.Prefix); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("cancelled authentication returned candidates", v, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.APIKeysByPrefix(t.Context(), key.Prefix); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction read credentials", err)
	}
}

func TestMemoryAPIKeyActivityRechecksIdentityLifecycleAndCommitsBothHeartbeats(t *testing.T) {
	for _, failure := range []string{"none", "collector", "expired", "revoked", "key-id"} {
		t.Run(failure, func(t *testing.T) {
			_, tx := memoryMembershipReadFixture(t)
			r, ok := tx.Repositories().Identity.(interface {
				RecordAPIKeyUse(context.Context, identitydomain.APIKey, identityapp.CollectorActivity) error
			})
			if !ok {
				t.Fatal("memory identity lacks atomic API-key activity")
			}
			at := fixedNow()
			expiry := at.Add(time.Hour)
			key := domain.APIKey{ID: "key", TenantID: "tenant", Name: "Collector", Prefix: "evy_test1234", Hash: strings.Repeat("a", 64), Scopes: []string{"evidence:write"}, ExpiresAt: &expiry, CreatedAt: at}
			tx.state.APIKeys[key.ID] = key
			tx.state.Collectors["collector"] = domain.Collector{ID: "collector", TenantID: "tenant", APIKeyID: key.ID}
			input := identitydomain.APIKey(key)
			input.LastUsedAt = &at
			activity := identityapp.CollectorActivity{ID: "collector", TenantID: "tenant", LastSeenAt: at}
			switch failure {
			case "collector":
				v := tx.state.Collectors["collector"]
				v.TenantID = "foreign"
				tx.state.Collectors[v.ID] = v
			case "expired":
				v := key
				v.ExpiresAt = &at
				tx.state.APIKeys[key.ID] = v
			case "revoked":
				v := key
				v.RevokedAt = &at
				tx.state.APIKeys[key.ID] = v
			case "key-id":
				v := key
				v.ID = "changed"
				tx.state.APIKeys[key.ID] = v
			}
			before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
			if err != nil {
				t.Fatal(err)
			}
			err = r.RecordAPIKeyUse(t.Context(), input, activity)
			if failure != "none" {
				if !errors.Is(err, ErrUnauthorized) || !reflect.DeepEqual(before, tx.state) {
					t.Fatal("failed activity changed key/collector or accepted stale state", err)
				}
				return
			}
			if err != nil || tx.state.APIKeys[key.ID].LastUsedAt == nil || tx.state.Collectors["collector"].LastSeenAt == nil {
				t.Fatal("activity lost atomic heartbeats", err)
			}
			past := at.Add(-time.Minute)
			input.LastUsedAt = &past
			activity.LastSeenAt = past
			if err := r.RecordAPIKeyUse(t.Context(), input, activity); err != nil || !tx.state.APIKeys[key.ID].LastUsedAt.Equal(at) || !tx.state.Collectors["collector"].LastSeenAt.Equal(at) {
				t.Fatal("activity timestamps went backwards", err)
			}
			if err := tx.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := r.RecordAPIKeyUse(t.Context(), input, activity); !errors.Is(err, ErrConflict) {
				t.Fatal("closed transaction accepted authentication activity", err)
			}
		})
	}
}
