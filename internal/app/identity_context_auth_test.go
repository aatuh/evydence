package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestLedgerIdentityTransactionRejectsStalePreloadedUser(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*Ledger, string)
	}{
		{
			name: "deactivated",
			mutate: func(ledger *Ledger, userID string) {
				user := ledger.users[userID]
				user.Status = "deactivated"
				user.DeactivatedAt = &now
				ledger.users[userID] = user
			},
		},
		{
			name: "deleted",
			mutate: func(ledger *Ledger, userID string) {
				delete(ledger.users, userID)
			},
		},
		{
			name: "moved to another tenant",
			mutate: func(ledger *Ledger, userID string) {
				user := ledger.users[userID]
				user.TenantID = "ten_other"
				ledger.users[userID] = user
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: func() time.Time { return now }})
			user := domain.HumanUser{ID: "usr_1", TenantID: "ten_1", Email: "user@example.test", Status: "active"}
			session := domain.SSOSession{
				ID: "sess_1", TenantID: user.TenantID, UserID: user.ID, ProviderID: "sso_1",
				Prefix: "evysso_prefix", Hash: "session-hash", ExpiresAt: now.Add(time.Hour),
			}
			ledger.users[user.ID] = user
			ledger.ssoSessions[session.ID] = session
			ledger.roleBindings["rb_1"] = domain.RoleBinding{
				ID: "rb_1", TenantID: user.TenantID, SubjectType: "user", SubjectID: user.ID,
				Role: "security_engineer", ResourceType: "tenant", ResourceID: user.TenantID,
			}

			identity, err := (ledgerIdentityReader{ledger: ledger}).SessionIdentity(context.Background(), ssoSessionToIdentityContext(session))
			if err != nil {
				t.Fatalf("preload session identity: %v", err)
			}
			if identity.User.Status != "active" || len(identity.Grants) == 0 {
				t.Fatalf("preloaded identity = %#v", identity)
			}

			ledger.mu.Lock()
			test.mutate(ledger, user.ID)
			err = newLedgerIdentityTransaction(ledger).ValidateActiveSession(context.Background(), ssoSessionToIdentityContext(session), now)
			ledger.mu.Unlock()

			if !errors.Is(err, identityapp.ErrUnauthorized) {
				t.Fatalf("ValidateActiveSession error = %v, want unauthorized", err)
			}
		})
	}
}

func TestLedgerIdentityTransactionRejectsAPIKeyExpiredBeforeActivityCommit(t *testing.T) {
	activityAt := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	expiresAt := activityAt
	preloaded := domain.APIKey{
		ID: "key_expiring", TenantID: "ten_1", Name: "short-lived", Prefix: "evy_short",
		Hash: "stored-hash", Scopes: []string{"evidence:read"}, ExpiresAt: &expiresAt,
		CreatedAt: activityAt.Add(-time.Hour),
	}
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: func() time.Time { return activityAt }})
	ledger.apiKeys[preloaded.ID] = preloaded
	activity := preloaded
	activity.LastUsedAt = &activityAt

	ledger.mu.Lock()
	tx := newLedgerIdentityTransaction(ledger)
	err := tx.UpdateAPIKeyActivity(context.Background(), apiKeyToIdentityContext(activity), identityapp.CollectorActivity{})
	ledger.mu.Unlock()

	if !errors.Is(err, identityapp.ErrUnauthorized) {
		t.Fatalf("UpdateAPIKeyActivity error = %v, want unauthorized", err)
	}
	if ledger.apiKeys[preloaded.ID].LastUsedAt != nil || len(tx.apiKeys) != 0 {
		t.Fatalf("expired key activity was staged: ledger=%#v transaction=%#v", ledger.apiKeys[preloaded.ID], tx.apiKeys)
	}
}
