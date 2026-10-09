package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type memoryVEXCompletionPort interface {
	CompleteVEXImportReport(context.Context, domain.VEXImportReport) error
}

func TestMemoryVEXReportCompletionIsConditionalOwnedDetachedAndTransactional(t *testing.T) {
	tx, _, _, _ := memoryVEXPointFixture(t)
	port, ok := tx.Repositories().Evidence.(memoryVEXCompletionPort)
	if !ok {
		t.Fatal("memory Evidence repository lacks scoped VEX report completion")
	}
	old := tx.state.VEXImportReports["report"]
	old.Status, old.FailureCode, old.FailureDetail = "accepted", "", ""
	tx.state.VEXImportReports[old.ID] = old
	complete := old
	complete.Status, complete.UpdatedAt = "parsed", old.UpdatedAt.Add(time.Second)
	complete.Warnings = []string{"completed limitation"}
	for _, change := range []string{"foreign", "source", "release", "artifact", "parser", "count", "schema", "created", "status", "negative", "backwards", "unsupported", "invalid"} {
		candidate := complete
		switch change {
		case "foreign":
			candidate.TenantID = "foreign"
		case "source":
			candidate.EvidenceID = "another"
		case "release":
			candidate.ReleaseID = "another"
		case "artifact":
			candidate.ArtifactID = "another"
		case "parser":
			candidate.ParserVersion = "another"
		case "count":
			candidate.StatementCount++
		case "schema":
			candidate.SchemaVersion = "another"
		case "created":
			candidate.CreatedAt = candidate.CreatedAt.Add(time.Second)
		case "status":
			candidate.Status = "accepted"
		case "negative":
			candidate.DecisionsCreated = -1
		case "backwards":
			candidate.UpdatedAt = old.UpdatedAt.Add(-time.Second)
		case "unsupported":
			candidate.UnsupportedFields = []string{"changed"}
		case "invalid":
			candidate.InvalidStatements = nil
		}
		if err := port.CompleteVEXImportReport(t.Context(), candidate); err == nil || !reflect.DeepEqual(tx.state.VEXImportReports[old.ID], old) {
			t.Fatal("invalid completion changed the accepted report", change, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := port.CompleteVEXImportReport(ctx, complete); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(tx.state.VEXImportReports[old.ID], old) {
		t.Fatal("canceled completion changed the report", err)
	}
	if err := port.CompleteVEXImportReport(t.Context(), complete); err != nil {
		t.Fatal(err)
	}
	complete.Warnings[0] = "caller mutation"
	if tx.state.VEXImportReports[old.ID].Warnings[0] != "completed limitation" {
		t.Fatal("completion stored caller-owned slices")
	}
	if err := port.CompleteVEXImportReport(t.Context(), complete); !errors.Is(err, ErrConflict) {
		t.Fatal("completion overwrote terminal history", err)
	}
	before, err := tx.factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	state, err := tx.factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, state) {
		t.Fatal("rolled back completion reached durable fixture state", err)
	}
}

func TestMemoryVEXReportCompletionRechecksParentsDuplicatesAndJSONBeforeWriting(t *testing.T) {
	for _, change := range []string{"missing-source", "foreign-artifact", "duplicate", "oversized", "late-cancel", "nil-context"} {
		t.Run(change, func(t *testing.T) {
			tx, _, _, _ := memoryVEXPointFixture(t)
			port := tx.Repositories().Evidence.(memoryVEXCompletionPort)
			old := tx.state.VEXImportReports["report"]
			old.Status, old.FailureCode, old.FailureDetail = "accepted", "", ""
			tx.state.VEXImportReports[old.ID] = old
			complete := old
			complete.Status, complete.UpdatedAt = "parsed", old.UpdatedAt.Add(time.Second)
			ctx := t.Context()
			switch change {
			case "missing-source":
				delete(tx.state.Evidence, old.EvidenceID)
			case "foreign-artifact":
				artifact := tx.state.Artifacts[old.ArtifactID]
				artifact.TenantID = "foreign"
				tx.state.Artifacts[artifact.ID] = artifact
			case "duplicate":
				duplicate := old
				duplicate.ID = "another"
				tx.state.VEXImportReports[duplicate.ID] = duplicate
			case "oversized":
				complete.Warnings = []string{strings.Repeat("x", 16<<20)}
			case "late-cancel":
				base, cancel := context.WithCancel(ctx)
				defer cancel()
				ctx = &memoryVEXCancelBeforeCompletionWrite{Context: base, cancel: cancel}
			case "nil-context":
				ctx = nil
			}
			before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
			if err != nil {
				t.Fatal(err)
			}
			err = port.CompleteVEXImportReport(ctx, complete)
			if err == nil || !reflect.DeepEqual(before, tx.state) {
				t.Fatal("invalid completion published report metadata", err)
			}
			if change == "late-cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("late cancellation did not stop the write", err)
			}
		})
	}
}

type memoryVEXCancelBeforeCompletionWrite struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *memoryVEXCancelBeforeCompletionWrite) Err() error {
	c.checks++
	if c.checks == 2 {
		c.cancel()
	}
	return c.Context.Err()
}
