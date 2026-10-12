package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestMemorySessionAuthenticationReadsCurrentOwnedRowsWithoutTrustOrPII(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	reader, ok := tx.Repositories().Identity.(interface {
		SessionsByPrefix(context.Context, string) ([]identitydomain.SSOSession, error)
		SessionIdentity(context.Context, identitydomain.SSOSession) (identityapp.SessionIdentity, error)
	})
	if !ok {
		t.Fatal("memory identity lacks native session authentication reads")
	}
	now := fixedNow()
	session := domain.SSOSession{ID: "session", TenantID: "tenant", UserID: "tenant-user", ProviderID: "provider", Prefix: "evysso_test1", Hash: strings.Repeat("a", 64), Groups: []string{"reviewers"}, ExpiresAt: now.Add(time.Hour), SchemaVersion: domain.SSOSessionSchemaVersion, CreatedAt: now}
	tx.state.SSOSessions[session.ID] = session
	u := tx.state.Users[session.UserID]
	u.Status, u.DisplayName = "active", strings.Repeat("unselected-private", 10000)
	tx.state.Users[u.ID] = u
	tx.state.SSOProviders[session.ProviderID] = domain.SSOProvider{ID: session.ProviderID, TenantID: "tenant", GroupsClaim: "groups", RoleMapping: map[string]string{"reviewers": "security_engineer"}, JWKS: map[string]any{"unselected": make(chan int)}}
	tx.state.RoleBindings["foreign"] = domain.RoleBinding{ID: "foreign", TenantID: "foreign", SubjectType: "user", SubjectID: u.ID, Role: "tenant_admin", ResourceType: "tenant", ResourceID: "foreign"}
	got, err := reader.SessionsByPrefix(t.Context(), session.Prefix)
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], identitydomain.SSOSession(session)) {
		t.Fatal("session candidate projection lost fields", got, err)
	}
	got[0].Groups[0] = "mutated"
	if tx.state.SSOSessions[session.ID].Groups[0] != "reviewers" {
		t.Fatal("candidate groups alias state")
	}
	identity, err := reader.SessionIdentity(t.Context(), identitydomain.SSOSession(session))
	if err != nil || identity.User.ID != u.ID || identity.User.Email != u.Email || identity.User.DisplayName != "" || len(identity.Grants) != 1 || identity.Grants[0].ResourceID != "" || identity.Grants[0].ResourceType != "" || identity.Grants[0].Role != "security_engineer" || !reflect.DeepEqual(identity.Grants[0].Scopes, identityapp.RoleScopes("security_engineer")) {
		t.Fatal("session identity read unrelated metadata or foreign grants", identity, err)
	}
	p := tx.state.SSOProviders[session.ProviderID]
	p.TenantID = "foreign"
	tx.state.SSOProviders[p.ID] = p
	identity, err = reader.SessionIdentity(t.Context(), identitydomain.SSOSession(session))
	if err != nil || len(identity.Grants) != 0 {
		t.Fatal("foreign provider supplied session grants", identity, err)
	}
	u.TenantID = "foreign"
	tx.state.Users[u.ID] = u
	if v, err := reader.SessionIdentity(t.Context(), identitydomain.SSOSession(session)); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, identityapp.SessionIdentity{}) {
		t.Fatal("foreign user returned identity", v, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := reader.SessionsByPrefix(ctx, session.Prefix); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("cancelled candidate read returned rows", v, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v, err := reader.SessionsByPrefix(t.Context(), session.Prefix); !errors.Is(err, ErrConflict) || v != nil {
		t.Fatal("closed transaction returned candidates", v, err)
	}
}

func TestMemorySessionActivityRejectsClosedTransactions(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	now := fixedNow()
	session := domain.SSOSession{ID: "session", TenantID: "tenant", UserID: "tenant-user", ProviderID: "provider", Prefix: "evysso_test12", Hash: strings.Repeat("a", 64), ExpiresAt: now.Add(time.Hour)}
	tx.state.SSOSessions[session.ID] = session
	u := tx.state.Users[session.UserID]
	u.Status = "active"
	tx.state.Users[u.ID] = u
	r := memoryIdentityRepository{uow: tx}
	if err := r.ValidateActiveSSOSession(t.Context(), session, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateActiveSSOSession(t.Context(), session, now); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction authenticated a session", err)
	}
}

func TestMemorySessionActivityRejectsChangedStoredIdentities(t *testing.T) {
	for _, target := range []string{"session-id", "user-id"} {
		t.Run(target, func(t *testing.T) {
			_, tx := memoryMembershipReadFixture(t)
			now := fixedNow()
			session := domain.SSOSession{ID: "session", TenantID: "tenant", UserID: "tenant-user", ProviderID: "provider", Prefix: "evysso_test1", Hash: strings.Repeat("a", 64), ExpiresAt: now.Add(time.Hour)}
			tx.state.SSOSessions[session.ID] = session
			u := tx.state.Users[session.UserID]
			u.Status = "active"
			tx.state.Users[session.UserID] = u
			if target == "session-id" {
				current := session
				current.ID = "changed"
				tx.state.SSOSessions[session.ID] = current
			} else {
				u.ID = "changed"
				tx.state.Users[session.UserID] = u
			}
			if err := (memoryIdentityRepository{uow: tx}).ValidateActiveSSOSession(t.Context(), session, now); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("changed stored identity authenticated", err)
			}
		})
	}
}

func TestMemorySessionAuthenticationRejectsExcessCandidatesAndGrantData(t *testing.T) {
	for _, target := range []string{"candidates", "groups", "grants", "mapping", "email"} {
		t.Run(target, func(t *testing.T) {
			_, tx := memoryMembershipReadFixture(t)
			now := fixedNow()
			session := domain.SSOSession{ID: "session", TenantID: "tenant", UserID: "tenant-user", ProviderID: "provider", Prefix: "evysso_test1", Hash: strings.Repeat("a", 64), ExpiresAt: now.Add(time.Hour), CreatedAt: now, SchemaVersion: domain.SSOSessionSchemaVersion}
			tx.state.SSOSessions[session.ID] = session
			r := memoryIdentityRepository{uow: tx}
			switch target {
			case "candidates":
				for i := 0; i < 64; i++ {
					v := session
					v.ID = fmt.Sprint("candidate-", i)
					tx.state.SSOSessions[v.ID] = v
				}
			case "groups":
				session.Groups = make([]string, 257)
				tx.state.SSOSessions[session.ID] = session
			case "grants":
				for i := 0; i < 257; i++ {
					id := fmt.Sprint("binding-", i)
					tx.state.RoleBindings[id] = domain.RoleBinding{ID: id, TenantID: "tenant", SubjectType: "user", SubjectID: session.UserID, Role: "security_engineer"}
				}
			case "mapping":
				tx.state.SSOProviders[session.ProviderID] = domain.SSOProvider{ID: session.ProviderID, TenantID: "tenant", RoleMapping: map[string]string{"group": strings.Repeat("x", 1<<20)}}
			case "email":
				u := tx.state.Users[session.UserID]
				u.Email = "invalid\x00email"
				tx.state.Users[u.ID] = u
			}
			if target == "candidates" || target == "groups" {
				if v, err := r.SessionsByPrefix(t.Context(), session.Prefix); !errors.Is(err, ErrConflict) || v != nil {
					t.Fatal("excess candidates/groups were truncated or accepted", len(v), err)
				}
			} else if v, err := r.SessionIdentity(t.Context(), identitydomain.SSOSession(session)); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, identityapp.SessionIdentity{}) {
				t.Fatal("excess/corrupt identity was accepted or returned partial state", v, err)
			}
		})
	}
}

func TestMemorySessionMetadataRevocationPreservesHashAndRejectsStaleCoordinates(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r := memoryIdentityRepository{uow: tx}
	writer, ok := tx.Repositories().Identity.(interface {
		RevokeSSOSessionMetadata(context.Context, identitydomain.SSOSession, time.Time) error
	})
	if !ok {
		t.Fatal("memory identity lacks native session revocation writer")
	}
	now := fixedNow()
	session := domain.SSOSession{ID: "session", TenantID: "tenant", UserID: "tenant-user", ProviderID: "provider", Prefix: "evysso_test12", Hash: strings.Repeat("a", 64), Groups: []string{"reviewers"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now, SchemaVersion: domain.SSOSessionSchemaVersion}
	tx.state.SSOSessions[session.ID] = session
	previous, err := r.ReadSSOSessionForRevocation(t.Context(), "tenant", session.ID)
	if err != nil || previous.Hash != "" {
		t.Fatal("revocation reader exposed hash", err)
	}
	stale := previous
	stale.Groups = []string{"changed"}
	if err := writer.RevokeSSOSessionMetadata(t.Context(), stale, now); !errors.Is(err, ErrConflict) || tx.state.SSOSessions[session.ID].RevokedAt != nil {
		t.Fatal("stale groups allowed revocation", err)
	}
	if err := writer.RevokeSSOSessionMetadata(t.Context(), previous, now); err != nil {
		t.Fatal(err)
	}
	stored := tx.state.SSOSessions[session.ID]
	if stored.Hash != session.Hash || stored.RevokedAt == nil || !stored.RevokedAt.Equal(now) {
		t.Fatal("metadata revocation lost hash or lifecycle", stored)
	}
	if err := writer.RevokeSSOSessionMetadata(t.Context(), previous, now); !errors.Is(err, ErrConflict) {
		t.Fatal("stale active metadata revoked again", err)
	}
}
