package postgres

import (
	"context"
	"sync"

	"github.com/aatuh/evydence/internal/app"
)

// AcquireRuntimeMigrationLease holds the shared schema coordinator throughout
// runtime startup, processing and drain. Release only after work has stopped,
// using the owner's bounded cleanup context. An expired cleanup retains it
// until a fresh explicit cleanup or process exit.
func (s *Store) AcquireRuntimeMigrationLease(ctx context.Context) (func(context.Context) error, error) {
	if ctx == nil || s == nil || s.pool == nil {
		return nil, app.ErrValidation
	}
	s.writerLeaseMu.Lock()
	defer s.writerLeaseMu.Unlock()
	minimum := int32(2)
	if s.writerLease != nil {
		minimum++
	}
	if s.runtimeMigrationLease != nil || s.pool.Config().MaxConns < minimum {
		return nil, ErrInvalidConfiguration
	}
	reader, err := s.acquireMigrationStateReader(ctx)
	if err != nil {
		return nil, err
	}
	s.runtimeMigrationLease = reader
	var once sync.Once
	var releaseErr error
	return func(cleanup context.Context) error {
		if cleanup == nil {
			return app.ErrValidation
		}
		if _, ok := cleanup.Deadline(); !ok {
			return app.ErrValidation
		}
		s.writerLeaseMu.Lock()
		defer s.writerLeaseMu.Unlock()
		if err := cleanup.Err(); err != nil {
			return err
		}
		once.Do(func() {
			releaseErr = reader.releaseWithin(cleanup)
			if s.runtimeMigrationLease == reader {
				s.runtimeMigrationLease = nil
			}
		})
		return releaseErr
	}, nil
}

// migrationStateView reuses the runtime's pinned session. A second shared
// acquisition could wait behind an exclusive migrator which is itself waiting
// for this runtime to stop. Keep pgx use and release serialized through finish.
func (s *Store) migrationStateView(ctx context.Context) (*migrationRunnerConnection, func() error, error) {
	if ctx == nil || s == nil || s.pool == nil {
		return nil, nil, app.ErrValidation
	}
	s.writerLeaseMu.Lock()
	if lease := s.runtimeMigrationLease; lease != nil {
		return lease, func() error {
			s.writerLeaseMu.Unlock()
			return nil
		}, nil
	}
	s.writerLeaseMu.Unlock()
	reader, err := s.acquireMigrationStateReader(ctx)
	if err != nil {
		return nil, nil, err
	}
	return reader, func() error { return reader.release(ctx) }, nil
}
