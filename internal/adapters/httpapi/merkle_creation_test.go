package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type merkleCreationHTTPFake struct {
	calls int
	err   error
}

func (f *merkleCreationHTTPFake) CreateMerkleBatch(_ context.Context, a identitydomain.Actor, _ verificationapp.CreateMerkleBatchInput) (verificationdomain.MerkleBatch, error) {
	f.calls++
	return verificationdomain.MerkleBatch{ID: "durable_batch", TenantID: a.TenantID, FromSequence: 1, ToSequence: 1, EntryCount: 1, RootHash: "root", LeafHashes: []string{"root"}, SignatureRefs: []string{"sig"}, SchemaVersion: verificationdomain.MerkleBatchSchemaVersion}, f.err
}
func TestMerkleCreationHTTPUsesFocusedCommandAndPreservesSafeReplay(t *testing.T) {
	local, secret := testServer(t)
	f := &merkleCreationHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{MerkleCreationCommands: f})
	if err != nil {
		t.Fatal(err)
	}
	s.verification = nil
	first := postJSON(t, s, secret, "/v1/merkle-batches", "durable-merkle", map[string]any{}, http.StatusCreated)
	if !strings.Contains(first, `"id":"durable_batch"`) || !strings.Contains(first, `"root_hash":"root"`) || f.calls != 1 {
		t.Fatal(first, f)
	}
	if replay := postJSON(t, s, secret, "/v1/merkle-batches", "durable-merkle", map[string]any{}, 201); replay != first || f.calls != 1 {
		t.Fatal("duplicate batch on replay", f)
	}
	for i, bad := range []string{`null`, `[]`, `{"from_sequence":null}`, `{"to_sequence":null}`, `{"from_sequence":"1"}`, `{"to_sequence":9223372036854775808}`, `{"from_sequence":1,"from_sequence":2}`, `{"unknown":1}`, `{} {}`} {
		postRaw(t, s, secret, "/v1/merkle-batches", fmt.Sprintf("bad-merkle-%d", i), []byte(bad), 400)
	}
	if f.calls != 1 {
		t.Fatal("malformed input reached signer", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrForbidden, 403}, {verificationapp.ErrValidation, 400}, {verificationapp.ErrConflict, 409}, {verificationapp.ErrNotFound, 404}, {errors.New("private SQL signing key bytes"), 500}} {
		f.err = tc.err
		before := f.calls
		body := postJSON(t, s, secret, "/v1/merkle-batches", fmt.Sprintf("failed-merkle-%d", i), map[string]any{}, tc.status)
		if f.calls != before+1 || strings.Contains(body, "private SQL") || strings.Contains(body, "durable_batch") {
			t.Fatal(body, f)
		}
	}
}
