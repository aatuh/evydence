package httpapi

import (
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestIntegrationFixtureRebindingPreservesExplicitDependenciesOnEveryPort(t *testing.T) {
	first := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	second := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	clock := &ssoFixtureRebindClock{at: peripheralFixtureQueryClock()}
	credentials := &collectorCountingCredentials{credentials: fixtureSessionCredentials("fixture")}
	configured := integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: first}, clock: clock, credentials: credentials}
	s := &Server{collectorCommands: configured, sourceRepositoryCommands: configured, sourceCommitCommands: configured, sourceBranchCommands: configured, pullRequestCommands: configured, sourceSnapshotCommands: configured}
	s.bindIntegrationFixtureCommands(second)
	for name, port := range map[string]any{"collector": s.collectorCommands, "repository": s.sourceRepositoryCommands, "commit": s.sourceCommitCommands, "branch": s.sourceBranchCommands, "pull-request": s.pullRequestCommands, "snapshot": s.sourceSnapshotCommands} {
		f, ok := port.(integrationFixtureCommands)
		if !ok || f.ledger != second || f.clock != clock || f.credentials != credentials {
			t.Errorf("%s rebinding discarded configured dependencies", name)
		}
	}
}

func TestIntegrationFixtureBindingPreservesExplicitPortsAndInitializesMissingPorts(t *testing.T) {
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	f := &failingIntegrationFixture{integrationFixtureCommands: integrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}}
	s := &Server{collectorCommands: f, sourceRepositoryCommands: f, sourceCommitCommands: f, sourceBranchCommands: f, pullRequestCommands: f, sourceSnapshotCommands: f}
	s.bindIntegrationFixtureCommands(ledger)
	if s.collectorCommands != f || s.sourceRepositoryCommands != f || s.sourceCommitCommands != f || s.sourceBranchCommands != f || s.pullRequestCommands != f || s.sourceSnapshotCommands != f {
		t.Fatal("binding replaced explicit integration command ports")
	}
	empty := &Server{}
	empty.bindIntegrationFixtureCommands(ledger)
	for name, port := range map[string]any{"collector": empty.collectorCommands, "repository": empty.sourceRepositoryCommands, "commit": empty.sourceCommitCommands, "branch": empty.sourceBranchCommands, "pull-request": empty.pullRequestCommands, "snapshot": empty.sourceSnapshotCommands} {
		f, ok := port.(integrationFixtureCommands)
		if !ok || f.ledger != ledger {
			t.Errorf("%s missing port was not initialized with the requested fixture", name)
		}
	}
}
