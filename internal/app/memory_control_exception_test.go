package app

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestMemoryExceptionInsertAcceptsOwnedControlAndRejectsForeignControl(t *testing.T) {
	_, tx := memoryGovernanceReadFixture(t)
	repository := tx.Repositories().Decisions
	exception := domain.Exception{ID: "owned-control-exception", TenantID: "tenant", ReleaseID: "tenant-release", ControlID: "tenant-control", Owner: "security", Reason: "Recorded exception", CreatedAt: fixedNow(), ExpiresAt: fixedNow().Add(time.Hour)}
	if err := repository.InsertException(t.Context(), exception); err != nil {
		t.Fatal("owned control-scoped exception rejected:", err)
	}
	if tx.state.Exceptions[exception.ID] != exception {
		t.Fatal("control-scoped exception lost fields")
	}
	for _, id := range []string{"foreign-control", "missing-control"} {
		before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
		if err != nil {
			t.Fatal(err)
		}
		invalid := exception
		invalid.ID, invalid.ControlID = id+"-exception", id
		if err := repository.InsertException(t.Context(), invalid); !errors.Is(err, ErrNotFound) {
			t.Fatal("unowned control-scoped exception accepted", id, err)
		}
		if !reflect.DeepEqual(before, tx.state) {
			t.Fatal("rejected control-scoped exception changed pending state")
		}
	}
}
