package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func (s *verificationTestState) ListLocalSigningKeysForUpdate(ctx context.Context, tenantID string) ([]verificationdomain.SigningKey, error) {
	return s.ListSigningKeys(ctx, tenantID)
}

func TestSigningKeyCommandsOwnAtomicRotationAndRevocation(t *testing.T) {
	state := newVerificationTestState()
	active, _ := verificationdomain.ParseSigningKeyStatus("active")
	state.keys["old"] = verificationdomain.SigningKey{ID: "old", TenantID: "ten_1", Provider: verificationdomain.SigningKeyDefaultProvider, Version: 3, Status: active}
	local := newVerificationTestService(t, state)
	commands, err := NewSigningKeyCommands(SigningKeyCommandConfig{Transactions: serviceSigningKeyTransactions{state}, KeyFactory: local.keyFactory, Authorizer: local.authorizer, Clock: local.clock, IDs: local.ids})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"bad\x00id", string([]byte{0xff})} {
		if _, err := commands.RevokeSigningKey(t.Context(), verificationTestActor(), id, SigningKeyRevocationInput{Reason: "incident"}); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid PostgreSQL text ID reached storage", err)
		}
	}
	if _, err := commands.RotateSigningKey(t.Context(), verificationTestActor(), "incident\x00reason"); !errors.Is(err, ErrValidation) {
		t.Fatal("null-byte rotation reason accepted", err)
	}
	if _, err := commands.RevokeSigningKey(t.Context(), verificationTestActor(), "old", SigningKeyRevocationInput{Reason: "incident\x00reason"}); !errors.Is(err, ErrValidation) {
		t.Fatal("null-byte revocation reason reached storage", err)
	}
	key, err := commands.RotateSigningKey(t.Context(), verificationTestActor(), "scheduled")
	if err != nil || key.Version != 4 || state.keys["old"].Status.String() != "retiring" || len(state.privateMaterial) != 1 || len(state.audit) != 1 {
		t.Fatalf("key=%#v err=%v", key, err)
	}
	state.auditErr = errVerificationTestFailure
	if result, err := commands.RevokeSigningKey(t.Context(), verificationTestActor(), key.ID, SigningKeyRevocationInput{Reason: "incident", Semantics: "compromised"}); !errors.Is(err, errVerificationTestFailure) || result.ID != "" || state.keys[key.ID].Status.String() != "active" {
		t.Fatal("failed revocation published state", err)
	}
	state.auditErr = nil
	revoked, err := commands.RevokeSigningKey(t.Context(), verificationTestActor(), key.ID, SigningKeyRevocationInput{Reason: "incident", Semantics: "compromised", HistoricalValidityPolicy: "invalidate_all"})
	if err != nil || revoked.Status.String() != "revoked" || revoked.CompromisedAt == nil || revoked.HistoricalValidityPolicy != "invalidate_all" || state.audit[1].EntryType != "signing_key.compromised" {
		t.Fatalf("revoked=%#v err=%v", revoked, err)
	}
	state.keys["overflow"] = verificationdomain.SigningKey{ID: "overflow", TenantID: "ten_1", Provider: verificationdomain.SigningKeyDefaultProvider, Version: 2147483647, Status: active}
	if result, err := commands.RotateSigningKey(t.Context(), verificationTestActor(), "overflow"); !errors.Is(err, ErrConflict) || result.ID != "" || len(state.audit) != 2 {
		t.Fatal("version overflow created state", err)
	}
}

type trackedKeyFactory struct {
	material []byte
	err      error
	invalid  bool
}

func (f *trackedKeyFactory) GenerateSigningKey(ctx context.Context, tenant, provider string, version int, now time.Time) (PreparedSigningKey, error) {
	prepared, err := (verificationTestKeyFactory{}).GenerateSigningKey(ctx, tenant, provider, version, now)
	f.material = prepared.PrivateMaterial
	if f.invalid {
		prepared.Key.Algorithm = ""
	}
	if f.err != nil {
		return prepared, f.err
	}
	return prepared, err
}

func TestSigningKeyCommandsClearGeneratedSecretsOnEveryExit(t *testing.T) {
	for _, mode := range []string{"success", "factory failure", "invalid material", "audit failure"} {
		t.Run(mode, func(t *testing.T) {
			state := newVerificationTestState()
			local := newVerificationTestService(t, state)
			factory := &trackedKeyFactory{}
			switch mode {
			case "factory failure":
				factory.err = errVerificationTestFailure
			case "invalid material":
				factory.invalid = true
			case "audit failure":
				state.auditErr = errVerificationTestFailure
			}
			commands, err := NewSigningKeyCommands(SigningKeyCommandConfig{Transactions: serviceSigningKeyTransactions{state}, KeyFactory: factory, Authorizer: local.authorizer, Clock: local.clock, IDs: local.ids})
			if err != nil {
				t.Fatal(err)
			}
			result, err := commands.RotateSigningKey(t.Context(), verificationTestActor(), "scheduled")
			if mode == "success" {
				if err != nil || result.ID == "" || string(state.privateMaterial[result.ID]) != "private-material" {
					t.Fatal("success did not preserve persisted secret", err)
				}
			} else if err == nil || result.ID != "" || len(state.keys) != 0 || len(state.audit) != 0 {
				t.Fatal("failure published state", err)
			}
			if len(factory.material) == 0 {
				t.Fatal("factory was not reached")
			}
			for _, b := range factory.material {
				if b != 0 {
					t.Fatal("generated transient key material retained")
				}
			}
		})
	}
}

func TestSigningKeyCommandsRejectRawInputBudgetsBeforeGeneratingOrWriting(t *testing.T) {
	state := newVerificationTestState()
	local := newVerificationTestService(t, state)
	factory := &trackedKeyFactory{}
	c, err := NewSigningKeyCommands(SigningKeyCommandConfig{Transactions: serviceSigningKeyTransactions{state}, KeyFactory: factory, Authorizer: local.authorizer, Clock: local.clock, IDs: local.ids})
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{strings.Repeat("r", 4097), strings.Repeat(" ", 4096) + "a"} {
		if _, err := c.RotateSigningKey(t.Context(), verificationTestActor(), reason); !errors.Is(err, ErrValidation) {
			t.Fatal("unbounded raw rotation reason", err)
		}
		if _, err := c.RevokeSigningKey(t.Context(), verificationTestActor(), "old", SigningKeyRevocationInput{Reason: reason}); !errors.Is(err, ErrValidation) {
			t.Fatal("unbounded raw revocation reason", err)
		}
	}
	if len(factory.material) != 0 || len(state.keys)+len(state.audit) != 0 {
		t.Fatal("bad input reached key generation/write")
	}
	for _, id := range []string{strings.Repeat("k", 1025), strings.Repeat(" ", 1024) + "k"} {
		if _, err := c.RevokeSigningKey(t.Context(), verificationTestActor(), id, SigningKeyRevocationInput{Reason: "incident"}); !errors.Is(err, ErrValidation) {
			t.Fatal("unbounded raw key ID", err)
		}
	}
}

type signingGuardOnlyTransaction struct {
	SigningKeyTransaction // All reads/writes panic if the guard reaches them.
	authorizations, locks int
	err                   error
}

func (t *signingGuardOnlyTransaction) Authorize(_ context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	t.authorizations++
	if a.TenantID != "ten_1" || r != (application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}) {
		return ErrForbidden
	}
	return t.err
}
func (t *signingGuardOnlyTransaction) LockSigningKeyScope(_ context.Context, tenant, id string) error {
	t.locks++
	if tenant != "ten_1" || id != "key" {
		return ErrNotFound
	}
	return t.err
}

type signingGuardOnlyTransactions struct{ tx *signingGuardOnlyTransaction }

func (t signingGuardOnlyTransactions) ExecuteSigningKeyCommand(ctx context.Context, run func(context.Context, SigningKeyTransaction) error) error {
	return run(ctx, t.tx)
}

func TestSigningKeyReplayGuardsNeverGenerateOrReadLifecycle(t *testing.T) {
	s := newVerificationTestService(t, newVerificationTestState())
	tx := &signingGuardOnlyTransaction{}
	factory := &trackedKeyFactory{}
	c, err := NewSigningKeyCommands(SigningKeyCommandConfig{Transactions: signingGuardOnlyTransactions{tx}, Authorizer: s.authorizer, KeyFactory: factory, Clock: application.ClockFunc(func() time.Time { panic("guard used clock") }), IDs: application.IDGeneratorFunc(func(string) string { panic("guard generated ID") })})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AuthorizeSigningKeyRotation(t.Context(), verificationTestActor()); err != nil {
		t.Fatal(err)
	}
	if err := c.AuthorizeSigningKeyRevocation(t.Context(), verificationTestActor(), " key "); err != nil {
		t.Fatal(err)
	}
	if tx.authorizations != 2 || tx.locks != 1 || len(factory.material) != 0 {
		t.Fatal("guard skipped current policy/ownership")
	}
	for _, failure := range []error{ErrNotFound, ErrConflict, ErrForbidden, errVerificationTestFailure} {
		tx.err = failure
		if err := c.AuthorizeSigningKeyRotation(t.Context(), verificationTestActor()); !errors.Is(err, failure) {
			t.Fatal("rotation guard suppressed failure", err)
		}
		if err := c.AuthorizeSigningKeyRevocation(t.Context(), verificationTestActor(), "key"); !errors.Is(err, failure) {
			t.Fatal("revocation guard suppressed failure", err)
		}
	}
	before := tx.authorizations
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.AuthorizeSigningKeyRotation(ctx, verificationTestActor()); !errors.Is(err, context.Canceled) || tx.authorizations != before {
		t.Fatal("cancelled guard reached transaction", err)
	}
}
