package app

import (
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestMemoryOpenAPIContractCopiesPreserveCompletionAndDetachOperations(t *testing.T) {
	for _, kind := range []string{"pending", "completed-empty", "completed-operations"} {
		t.Run(kind, func(t *testing.T) {
			tx, _ := memoryParsedPointFixture(t)
			c := tx.state.OpenAPIContracts["contract"]
			switch kind {
			case "pending":
				c.PathCount, c.Operations = 0, nil
			case "completed-empty":
				c.PathCount, c.Operations = 0, []domain.OpenAPIOperation{}
			}
			delete(tx.state.OpenAPIContracts, c.ID)
			if err := tx.Repositories().Evidence.InsertOpenAPIContract(t.Context(), c); err != nil {
				t.Fatal(err)
			}
			stored, err := tx.Repositories().Evidence.GetOpenAPIContract(t.Context(), "tenant", c.ID)
			if err != nil || !reflect.DeepEqual(stored, c) {
				t.Fatal("contract insertion or read changed parser completion state", err)
			}
			if len(c.Operations) != 0 {
				c.Operations[0].RequiredRequestFields[0] = "input-mutation"
				stored.Operations[0].ResponseStatuses[0] = "read-mutation"
				if tx.state.OpenAPIContracts[c.ID].Operations[0].RequiredRequestFields[0] == "input-mutation" || tx.state.OpenAPIContracts[c.ID].Operations[0].ResponseStatuses[0] == "read-mutation" {
					t.Fatal("insert or read retained caller-owned contract fields")
				}
			}
			want := tx.state.OpenAPIContracts[c.ID]
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			snapshot, err := tx.factory.Snapshot()
			if err != nil || !reflect.DeepEqual(snapshot.OpenAPIContracts[c.ID], want) {
				t.Fatal("commit or snapshot changed contract completion state", err)
			}
			if len(want.Operations) != 0 {
				want.Operations[0].RequiredRequestFields[0] = "post-commit-mutation"
				snapshot.OpenAPIContracts[c.ID].Operations[0].ResponseStatuses[0] = "snapshot-mutation"
			}
			next, err := tx.factory.BeginUnitOfWork(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := next.Rollback(t.Context()); err != nil {
					t.Error(err)
				}
			}()
			current, err := next.Repositories().Evidence.GetOpenAPIContract(t.Context(), "tenant", c.ID)
			if err != nil || (current.Operations == nil) != (kind == "pending") || len(current.Operations) != len(c.Operations) {
				t.Fatal("new transaction changed contract completion state", err)
			}
			if len(current.Operations) != 0 && (current.Operations[0].RequiredRequestFields[0] == "post-commit-mutation" || current.Operations[0].ResponseStatuses[0] == "snapshot-mutation") {
				t.Fatal("transaction copies share mutable contract operation fields")
			}
		})
	}
}
