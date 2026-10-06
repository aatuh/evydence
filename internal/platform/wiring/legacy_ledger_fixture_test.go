package wiring

import (
	"context"

	"github.com/aatuh/evydence/internal/adapters/verification/dsse"
	"github.com/aatuh/evydence/internal/app"
)

// Concrete adapters belong to outer wiring, including test fixture setup.
// These helpers preserve existing test inputs and assertions without restoring
// implicit production defaults in the legacy application constructor.
func legacyLedgerFixtureConfig(cfg app.Config) app.Config {
	if cfg.BuildAttestationParser == nil {
		cfg.BuildAttestationParser = dsse.BuildAttestationIngestionParser{}
	}
	if cfg.DSSEPolicyVerifier == nil {
		cfg.DSSEPolicyVerifier = dsse.PolicyVerifier{}
	}
	return cfg
}

func newLegacyLedgerFixtureWithContext(ctx context.Context, cfg app.Config) (*app.Ledger, error) {
	return app.NewLedgerWithContext(ctx, legacyLedgerFixtureConfig(cfg))
}
