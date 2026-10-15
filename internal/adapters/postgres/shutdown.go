package postgres

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

// WaitForIdle is called only after request/job admission and processing stop.
// Keep the writer lease until all command and package-read borrowers return.
// The dedicated writer connection is owned infrastructure, not active work.
func (s *Store) WaitForIdle(ctx context.Context) error {
	if ctx == nil {
		return app.ErrValidation
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s == nil || s.pool == nil {
			return nil
		}
		s.writerLeaseMu.RLock()
		var owned int32
		if s.writerLease != nil {
			owned = 1
		}
		acquired := s.pool.Stat().AcquiredConns()
		s.writerLeaseMu.RUnlock()
		readIdle := s.packageReadPool == nil || s.packageReadPool.Stat().AcquiredConns() == 0
		if acquired <= owned && readIdle {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
