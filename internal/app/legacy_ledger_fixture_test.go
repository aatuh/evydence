package app

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/verification/dsse"
)

// Concrete adapters belong to outer wiring, including test fixture setup.
// These helpers preserve existing test inputs and assertions without restoring
// implicit production defaults in the legacy application constructor.
func legacyLedgerFixtureConfig(cfg Config) Config {
	if cfg.BuildAttestationParser == nil {
		cfg.BuildAttestationParser = dsse.BuildAttestationIngestionParser{}
	}
	if cfg.DSSEPolicyVerifier == nil {
		cfg.DSSEPolicyVerifier = dsse.PolicyVerifier{}
	}
	return cfg
}

func newLegacyLedgerFixture(cfg Config) *Ledger {
	return NewLedger(legacyLedgerFixtureConfig(cfg))
}

func newLegacyLedgerFixtureWithContext(ctx context.Context, cfg Config) (*Ledger, error) {
	return NewLedgerWithContext(ctx, legacyLedgerFixtureConfig(cfg))
}
