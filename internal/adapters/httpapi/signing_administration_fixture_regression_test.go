package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type failingSigningAdministrationFixtureCommands struct {
	signingAdministrationFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingSigningAdministrationFixtureCommands) failAfterWrite(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private signing fixture failure")
}

func (f *failingSigningAdministrationFixtureCommands) RotateSigningKey(ctx context.Context, actor domain.Actor, reason string) (verificationdomain.SigningKey, error) {
	value, err := f.signingAdministrationFixtureCommands.RotateSigningKey(ctx, actor, reason)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func (f *failingSigningAdministrationFixtureCommands) RevokeSigningKey(ctx context.Context, actor domain.Actor, id string, input verificationapp.SigningKeyRevocationInput) (verificationdomain.SigningKey, error) {
	value, err := f.signingAdministrationFixtureCommands.RevokeSigningKey(ctx, actor, id, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func (f *failingSigningAdministrationFixtureCommands) CreateSigningProvider(ctx context.Context, actor domain.Actor, input verificationapp.CreateSigningProviderInput) (verificationdomain.SigningProvider, error) {
	value, err := f.signingAdministrationFixtureCommands.CreateSigningProvider(ctx, actor, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func (f *failingSigningAdministrationFixtureCommands) CreateDSSETrustRoot(ctx context.Context, actor domain.Actor, input verificationapp.CreateDSSETrustRootInput) (verificationdomain.DSSETrustRoot, error) {
	value, err := f.signingAdministrationFixtureCommands.CreateDSSETrustRoot(ctx, actor, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func TestSigningAdministrationFixtureCommandsRollBackAllEffectsAfterWriteFailure(t *testing.T) {
	for _, action := range []string{"rotate", "revoke", "provider", "root"} {
		t.Run(action, func(t *testing.T) {
			factory := app.NewMemoryUnitOfWorkFactory()
			ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
			scope := seedEvidenceFixtureScope(t, ledger, "Fixture")
			keysBefore, err := ledger.ListSigningKeys(t.Context(), scope.actor)
			if err != nil || len(keysBefore) != 1 {
				t.Fatal("missing initial fixture signing key", err)
			}
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			// Authentication heartbeats are outside the command under test.
			server.authn = &configuredAuthenticator{actor: scope.actor}
			commands := &failingSigningAdministrationFixtureCommands{signingAdministrationFixtureCommands: signingAdministrationFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.signingKeyCommands, server.trustConfigurationCommands = commands, commands
			path, body := "/v1/signing-keys/rotate", `{"reason":"scheduled"}`
			switch action {
			case "revoke":
				path = "/v1/signing-keys/" + keysBefore[0].ID + "/revoke"
				body = `{"reason":"incident","semantics":"compromised","historical_validity_policy":"invalidate_all"}`
			case "provider":
				path, body = "/v1/signing-providers", `{"name":"KMS","type":"aws_kms","key_ref":"key","encrypted":true}`
			case "root":
				path, body = "/v1/dsse-trust-roots", `{"name":"Builder","key_id":"builder-key","algorithm":"Ed25519","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","allowed_predicate_types":["https://slsa.dev/provenance/v1"],"expected_builder_ids":["builder"],"required_claims":["builder_id"]}`
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, scope.secret, path, "fixture-signing-failure", []byte(body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, `"data"`) || strings.Contains(out, "private signing") || strings.Contains(out, `"private"`) {
				t.Fatal("failed signing command bypassed isolation or exposed partial effects")
			}
			// Revocation reuses the public request ID in the Problem instance;
			// newly allocated IDs must not be disclosed on failure.
			if action != "revoke" && strings.Contains(out, commands.changedID) {
				t.Fatal("failed signing command disclosed a new result ID")
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed signing command lost its replay failure record")
			}
			for _, record := range after.Idempotency {
				if record.State != app.IdempotencyFailed || record.Response != nil || record.Status != 0 {
					t.Fatal("failed signing command stored a partial response")
				}
			}
			// After checking the intentional failure record, compare all other
			// effects, including key material/lifecycle, trust metadata and audit.
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed signing command committed repository effects")
			}
			keysAfter, err := ledger.ListSigningKeys(t.Context(), scope.actor)
			if err != nil || !reflect.DeepEqual(keysBefore, keysAfter) {
				t.Fatal("failed signing command published changed key lifecycle", err)
			}
		})
	}
}

func TestSigningAdministrationFixtureGuardsKeepTenantAuthorityAndReadOnlyState(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	keys, err := ledger.ListSigningKeys(t.Context(), owner.actor)
	if err != nil || len(keys) != 1 {
		t.Fatal("missing owner key", err)
	}
	commands := signingAdministrationFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	checks := []struct {
		name string
		run  func(context.Context, domain.Actor) error
	}{
		{"rotate", commands.AuthorizeSigningKeyRotation},
		{"trust", commands.AuthorizeTrustConfiguration},
		{"revoke", func(ctx context.Context, actor domain.Actor) error {
			return commands.AuthorizeSigningKeyRevocation(ctx, actor, keys[0].ID)
		}},
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(t.Context(), owner.actor); err != nil {
				t.Fatal("fixture guard rejected current authority", err)
			}
			denied := owner.actor
			denied.Scopes = []string{"keys:read"}
			if err := tc.run(t.Context(), denied); !errors.Is(err, application.ErrForbidden) && !errors.Is(err, app.ErrForbidden) {
				t.Fatal("fixture guard skipped keys administration", err)
			}
			human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"*"}}}}
			if err := tc.run(t.Context(), human); !errors.Is(err, application.ErrForbidden) && !errors.Is(err, app.ErrForbidden) {
				t.Fatal("product grant became tenant-wide key authority", err)
			}
			human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: human.TenantID, Scopes: []string{"keys:admin"}}}
			if err := tc.run(t.Context(), human); err != nil {
				t.Fatal("fixture guard rejected current tenant-wide human grant", err)
			}
			human.ResourceGrants = nil
			if err := tc.run(t.Context(), human); !errors.Is(err, application.ErrForbidden) && !errors.Is(err, app.ErrForbidden) {
				t.Fatal("removed human grant retained authority", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := tc.run(ctx, owner.actor); !errors.Is(err, context.Canceled) {
				t.Fatal("fixture guard ignored cancellation", err)
			}
		})
	}
	if err := commands.AuthorizeSigningKeyRevocation(t.Context(), foreign.actor, keys[0].ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign tenant could administer owner key", err)
	}
	if err := commands.AuthorizeSigningKeyRevocation(t.Context(), owner.actor, "missing-key"); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("missing key ownership was accepted", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read-only signing guards changed repository state", err)
	}
}
