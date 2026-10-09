package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type localProofFetchFixture struct {
	calls   int
	result  TransparencyProofResult
	onFetch func()
}

func (f *localProofFetchFixture) FetchTransparencyProof(context.Context, TransparencyProofRequest) (TransparencyProofResult, error) {
	f.calls++
	if f.onFetch != nil {
		f.onFetch()
	}
	return f.result, nil
}
func TestPublicTransparencyFetchRejectsBeforeProviderAndChangedSnapshot(t *testing.T) {
	for _, mode := range []string{"checkpoint", "batch", "human-product", "changed-entry"} {
		t.Run(mode, func(t *testing.T) {
			l, a, v := publicProofLocalFixture(t)
			log := l.publicLogs["log"]
			log.Endpoint = "https://log.example.test"
			l.publicLogs["log"] = log
			f := &localProofFetchFixture{result: TransparencyProofResult{RootHash: v.EntryHash, TreeSize: 1}}
			l.transparencyProofs = f
			want, calls := ErrNotFound, 0
			switch mode {
			case "checkpoint":
				delete(l.transparency, "cp")
			case "batch":
				x := l.merkleBatches["batch"]
				x.TenantID = "other"
				l.merkleBatches["batch"] = x
			case "human-product":
				a.KeyID, a.UserID = "", "user"
				a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"keys:admin"}}}
				want = ErrForbidden
			case "changed-entry":
				want, calls = ErrConflict, 1
				f.onFetch = func() {
					l.mu.Lock()
					defer l.mu.Unlock()
					x := l.publicLogEntries[v.ID]
					x.ExternalID = "changed"
					l.publicLogEntries[v.ID] = x
				}
			}
			out, err := l.FetchAndVerifyPublicTransparencyLogEntry(t.Context(), a, v.ID)
			if !errors.Is(err, want) || out.ID != "" || f.calls != calls {
				t.Fatal("unowned/stale fetched proof assessed", mode, out, err, f.calls)
			}
		})
	}
}
