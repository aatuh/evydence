package query

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// OutboxCounts is a payload-free database projection, not a domain entity.
type OutboxCounts struct {
	PendingJobs            int
	RunningJobs            int
	TerminalJobs           int
	OldestPendingCreatedAt time.Time
}

type OutboxDiagnosticsReader interface {
	ReadOutboxCounts(context.Context) (OutboxCounts, error)
}

type OutboxDiagnostics struct {
	reader OutboxDiagnosticsReader
}

func NewOutboxDiagnostics(reader OutboxDiagnosticsReader) (*OutboxDiagnostics, error) {
	if reader == nil {
		return nil, ErrValidation
	}
	return &OutboxDiagnostics{reader: reader}, nil
}

// Diagnostics authorizes before accessing global queue health. No job IDs,
// tenant labels, payloads, or failure details are returned.
func (s *OutboxDiagnostics) Diagnostics(ctx context.Context, actor identitydomain.Actor) (OutboxCounts, error) {
	var empty OutboxCounts
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := application.AuthorizeInstanceScope(ctx, actor, "instance:admin"); err != nil {
		return empty, err
	}
	result, err := s.reader.ReadOutboxCounts(ctx)
	if err != nil {
		return empty, err
	}
	if result.PendingJobs < 0 || result.RunningJobs < 0 || result.TerminalJobs < 0 ||
		(result.PendingJobs > 0 && result.OldestPendingCreatedAt.IsZero()) ||
		(result.PendingJobs == 0 && !result.OldestPendingCreatedAt.IsZero()) {
		return empty, ErrInvalidProjection
	}
	return result, nil
}
