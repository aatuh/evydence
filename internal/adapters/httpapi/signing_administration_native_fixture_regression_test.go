package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestSigningAdministrationNativeFixtureUsesCurrentRepositoriesWithoutAggregateClock(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("signing administration used aggregate clock") }})
	f := signingAdministrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	guard := f
	guard.clock = application.ClockFunc(func() time.Time { panic("signing replay guard allocated time") })
	if err := guard.AuthorizeSigningKeyRotation(t.Context(), owner.actor); err != nil {
		t.Fatal("rotation guard used missing aggregate tenant", err)
	}
	if err := guard.AuthorizeTrustConfiguration(t.Context(), owner.actor); err != nil {
		t.Fatal("trust guard used missing aggregate tenant", err)
	}
	for _, key := range before.SigningKeys {
		if err := guard.AuthorizeSigningKeyRevocation(t.Context(), owner.actor, key.ID); err != nil {
			t.Fatal("revocation guard used missing aggregate cache", err)
		}
	}
	guarded, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(guarded, before) {
		t.Fatal("signing replay guard wrote effects", err)
	}
	rotated, err := f.RotateSigningKey(t.Context(), owner.actor, "scheduled")
	if err != nil || rotated.ID == "" || rotated.TenantID != owner.actor.TenantID || rotated.Version != 2 || rotated.Status.String() != "active" {
		t.Fatal("focused rotation lost current key lifecycle", err)
	}
	after, err := factory.Snapshot()
	if err != nil || len(after.SigningKeys) != len(before.SigningKeys)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 {
		t.Fatal("rotation did not commit key and audit", err)
	}
	for id, prior := range before.SigningKeys {
		current := after.SigningKeys[id]
		if current.Status != "retiring" || !reflect.DeepEqual(current.Private, prior.Private) {
			t.Fatal("rotation lost retired private material or lifecycle")
		}
	}
	revoked, err := f.RevokeSigningKey(t.Context(), owner.actor, rotated.ID, verificationapp.SigningKeyRevocationInput{Reason: "incident", Semantics: "compromised", HistoricalValidityPolicy: "invalidate_all"})
	if err != nil || revoked.Status.String() != "revoked" || revoked.CompromisedAt == nil || revoked.RevokedAt == nil || revoked.HistoricalValidityPolicy != "invalidate_all" {
		t.Fatal("revocation lost compromise semantics", err)
	}
}

func TestSigningAdministrationNativeFixtureTrustCreationAndCommitFailureAreAtomic(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	failure := &bundleWriteFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: failure, Now: func() time.Time { panic("trust creation used aggregate clock") }})
	f := signingAdministrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	provider, err := f.CreateSigningProvider(t.Context(), owner.actor, verificationapp.CreateSigningProviderInput{Name: "Recorded KMS", Type: "aws_kms", KeyRef: "public-key-reference", Encrypted: true})
	if err != nil || provider.ID == "" || provider.TenantID != owner.actor.TenantID || provider.Type != "aws_kms" {
		t.Fatal("focused provider creation lost metadata", err)
	}
	input := verificationapp.CreateDSSETrustRootInput{Name: "Builder", KeyID: "builder-key", Algorithm: "Ed25519", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedPredicateTypes: []string{"https://slsa.dev/provenance/v1"}, ExpectedBuilderIDs: []string{"builder"}, RequiredClaims: []string{"builder_id"}}
	root, err := f.CreateDSSETrustRoot(t.Context(), owner.actor, input)
	if err != nil || root.ID == "" || root.KeyID != input.KeyID || len(root.ExpectedBuilderIDs) != 1 {
		t.Fatal("focused trust creation lost policy", err)
	}
	root.ExpectedBuilderIDs[0] = "changed"
	before, err := base.Snapshot()
	if err != nil || before.DSSETrustRoots[root.ID].ExpectedBuilderIDs[0] != "builder" {
		t.Fatal("trust result aliases stored policy", err)
	}
	for _, run := range []func() error{
		func() error {
			var id string
			for keyID, key := range before.SigningKeys {
				if key.TenantID == owner.actor.TenantID {
					id = keyID
				}
			}
			v, err := f.RevokeSigningKey(t.Context(), owner.actor, id, verificationapp.SigningKeyRevocationInput{Reason: "incident", Semantics: "compromised", HistoricalValidityPolicy: "invalidate_all"})
			if !reflect.DeepEqual(v, verificationdomain.SigningKey{}) {
				t.Fatal("failed revocation exposed lifecycle metadata")
			}
			return err
		},
		func() error {
			v, err := f.RotateSigningKey(t.Context(), owner.actor, "scheduled")
			if !reflect.DeepEqual(v, verificationdomain.SigningKey{}) {
				t.Fatal("failed rotation exposed key metadata")
			}
			return err
		},
		func() error {
			v, err := f.CreateSigningProvider(t.Context(), owner.actor, verificationapp.CreateSigningProviderInput{Name: "Rollback", Type: "aws_kms", KeyRef: "public", Encrypted: true})
			if !reflect.DeepEqual(v, verificationdomain.SigningProvider{}) {
				t.Fatal("failed provider creation exposed metadata")
			}
			return err
		},
		func() error {
			input.KeyID = "rollback-key"
			v, err := f.CreateDSSETrustRoot(t.Context(), owner.actor, input)
			if !reflect.DeepEqual(v, verificationdomain.DSSETrustRoot{}) {
				t.Fatal("failed trust creation exposed policy")
			}
			return err
		},
	} {
		failure.failAt = failure.begins + 1
		if err := run(); err == nil || failure.begins != failure.failAt {
			t.Fatal("write commit failure was not exercised", err)
		}
		after, err := base.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("failed signing/trust commit left partial effects", err)
		}
	}
}

func TestSigningAdministrationNativeFixtureBindingPreservesClockAndInjectedPorts(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	old := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	f := signingAdministrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: old}, clock: application.ClockFunc(func() time.Time { return at })}
	s := &Server{signingKeyCommands: f, trustConfigurationCommands: f}
	s.bindSigningAdministrationFixturePorts(ledger)
	for _, value := range []any{s.signingKeyCommands, s.trustConfigurationCommands} {
		bound, ok := value.(signingAdministrationFixtureCommands)
		if !ok || bound.ledger != ledger || bound.clock == nil || !bound.clock.Now().Equal(at) {
			t.Fatal("signing fixture rebinding lost current repository or explicit clock")
		}
	}
	keys, trust := &signingKeyHTTPFake{}, &trustConfigurationHTTPFake{}
	s.signingKeyCommands, s.trustConfigurationCommands = keys, trust
	s.bindSigningAdministrationFixturePorts(ledger)
	if s.signingKeyCommands != keys || s.trustConfigurationCommands != trust {
		t.Fatal("signing fixture replaced explicit focused ports")
	}
}

func TestSigningAdministrationNativeFixtureRejectsMissingRepositoriesAndRevokedGrants(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture"})
	f := signingAdministrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	actor := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{app.ScopeKeysAdmin}}
	if err := f.AuthorizeTrustConfiguration(t.Context(), actor); !errors.Is(err, app.ErrValidation) {
		t.Fatal("missing trust repository used aggregate fallback", err)
	}
	if v, err := f.RotateSigningKey(t.Context(), actor, "scheduled"); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, verificationdomain.SigningKey{}) {
		t.Fatal("missing key repository returned a result", err)
	}
	actor.Scopes = nil
	if err := f.AuthorizeSigningKeyRotation(t.Context(), actor); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("removed scope reached signing storage", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.AuthorizeTrustConfiguration(ctx, actor); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled trust preflight reached storage", err)
	}
}
