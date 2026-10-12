package app

import (
	"context"
	"errors"
	"testing"

	releaseapp "github.com/aatuh/evydence/internal/release/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type dsseConstructorStoreTrap struct{ loads int }

func (s *dsseConstructorStoreTrap) LoadState(context.Context) (PersistedState, bool, error) {
	s.loads++
	return PersistedState{}, false, nil
}
func (*dsseConstructorStoreTrap) SaveState(context.Context, PersistedState) error { return nil }

func TestLedgerRequiresExplicitDSSEPortsBeforeStateLoading(t *testing.T) {
	store := &dsseConstructorStoreTrap{}
	ledger, err := NewLedgerWithContext(t.Context(), Config{Store: store})
	if err == nil || ledger != nil || store.loads != 0 {
		t.Fatalf("implicit DSSE adapters remain in core or state was read: ledger=%v err=%v loads=%d", ledger != nil, err, store.loads)
	}
}

type dsseParserPortStub struct{}

func (*dsseParserPortStub) ParseBuildAttestation(context.Context, releaseapp.BuildAttestationPayloadSource) (releaseapp.ParsedBuildAttestation, error) {
	return releaseapp.ParsedBuildAttestation{}, ErrValidation
}

type dssePolicyPortStub struct{}

func (*dssePolicyPortStub) VerifyDSSEPolicies(context.Context, verificationapp.DSSEPolicyVerification) (verificationapp.DSSEVerificationFacts, error) {
	return verificationapp.DSSEVerificationFacts{}, ErrValidation
}

func TestLedgerRejectsEachMissingOrTypedNilDSSEPortBeforeStorage(t *testing.T) {
	base := Config{BuildAttestationParser: &dsseParserPortStub{}, DSSEPolicyVerifier: &dssePolicyPortStub{}}
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"missing parser", func(c *Config) { c.BuildAttestationParser = nil }},
		{"typed-nil parser", func(c *Config) { c.BuildAttestationParser = (*dsseParserPortStub)(nil) }},
		{"missing verifier", func(c *Config) { c.DSSEPolicyVerifier = nil }},
		{"typed-nil verifier", func(c *Config) { c.DSSEPolicyVerifier = (*dssePolicyPortStub)(nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.edit(&cfg)
			store := &dsseConstructorStoreTrap{}
			cfg.Store = store
			if ledger, err := NewLedgerWithContext(t.Context(), cfg); err == nil || ledger != nil || store.loads != 0 {
				t.Fatal("missing DSSE port reached state", ledger != nil, err, store.loads)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := NewLedgerWithContext(ctx, Config{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost before port validation", err)
	}
	if _, err := NewLedgerWithContext(nil, base); !errors.Is(err, ErrValidation) { //nolint:staticcheck // Defensive nil-context rejection.
		t.Fatal("nil context accepted", err)
	}
}

func TestIdempotencyClonePreservesExplicitDSSEPorts(t *testing.T) {
	parser, verifier := &dsseParserPortStub{}, &dssePolicyPortStub{}
	ledger, err := NewLedgerWithContext(t.Context(), Config{BuildAttestationParser: parser, DSSEPolicyVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	clone, err := ledger.cloneForIdempotencyCommand(t.Context())
	if err != nil || clone.buildAttestationParser != parser || clone.dssePolicyVerifier != verifier {
		t.Fatal("idempotency clone lost inward DSSE ports", err)
	}
}
