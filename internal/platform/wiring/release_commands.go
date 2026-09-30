package wiring

import (
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	application "github.com/aatuh/evydence/internal/application"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// BuildReleaseCommands binds tenant-scoped product reads and version-unique
// release writes to focused ports, without loading Ledger state.
func BuildReleaseCommands(reader releaseapp.ReleaseReader, factory app.UnitOfWorkFactory) (*releaseapp.ReleaseCommands, error) {
	if reader == nil || factory == nil {
		return nil, errors.New("release reader and transactions are required")
	}
	return releaseapp.NewReleaseCommands(releaseapp.ReleaseCommandConfig{
		Reader:       catalogParentReader{source: reader},
		Authorizer:   releasequery.NewCatalogAuthorizer(),
		Transactions: catalogTransactions{factory: factory},
		Clock:        application.ClockFunc(time.Now),
		IDs:          application.IDGeneratorFunc(application.NewID),
	})
}
