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

type recordedCheckpointHTTPFake struct {
	calls int
	err   error
}

func (f *recordedCheckpointHTTPFake) CreateTransparencyCheckpoint(_ context.Context, a identitydomain.Actor, in verificationapp.CreateTransparencyCheckpointInput) (verificationdomain.TransparencyCheckpoint, error) {
	f.calls++
	return verificationdomain.TransparencyCheckpoint{ID: "durable_checkpoint", TenantID: a.TenantID, BatchID: in.BatchID, Provider: in.Provider, ExternalID: in.ExternalID, ExternalURL: in.ExternalURL, State: "recorded", TimestampHash: "sha256:assertion", SchemaVersion: verificationdomain.TransparencyCheckpointVersion}, f.err
}
func TestRecordedTransparencyCheckpointHTTPUsesFocusedCommandAndSafeReplay(t *testing.T) {
	local, secret := testServer(t)
	f := &recordedCheckpointHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{TransparencyCheckpointCommands: f})
	if err != nil {
		t.Fatal(err)
	}
	s.verification = nil
	body := map[string]any{"batch_id": "batch", "provider": "provider", "external_id": "record"}
	first := postJSON(t, s, secret, "/v1/transparency-checkpoints", "focused-checkpoint", body, http.StatusCreated)
	if !strings.Contains(first, `"id":"durable_checkpoint"`) || !strings.Contains(first, `"state":"recorded"`) || strings.Contains(first, `"state":"passed"`) || f.calls != 1 {
		t.Fatal(first, f)
	}
	if replay := postJSON(t, s, secret, "/v1/transparency-checkpoints", "focused-checkpoint", body, http.StatusCreated); replay != first || f.calls != 1 {
		t.Fatal("duplicate checkpoint", f)
	}
	for i, bad := range []string{`null`, `[]`, `{"batch_id":null,"provider":"provider","external_id":"record"}`, `{"batch_id":"batch","provider":null,"external_id":"record"}`, `{"batch_id":"batch","provider":"provider","external_id":null}`, `{"batch_id":"batch","provider":"provider","external_url":null,"external_id":"record"}`, `{"batch_id":1,"provider":"provider","external_id":"record"}`, `{"batch_id":"a","batch_id":"b","provider":"provider","external_id":"record"}`, `{"batch_id":"batch","provider":"provider","external_id":"record","extra":1}`, `{"batch_id":"batch","provider":"provider","external_id":"record"} {}`} {
		postRaw(t, s, secret, "/v1/transparency-checkpoints", fmt.Sprintf("bad-checkpoint-%d", i), []byte(bad), http.StatusBadRequest)
	}
	if f.calls != 1 {
		t.Fatal("malformed checkpoint reached command", f)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{verificationapp.ErrNotFound, 404}, {verificationapp.ErrForbidden, 403}, {verificationapp.ErrValidation, 400}, {verificationapp.ErrConflict, 409}, {errors.New("private SQL checkpoint root"), 500}} {
		f.err = tc.err
		before := f.calls
		response := postJSON(t, s, secret, "/v1/transparency-checkpoints", fmt.Sprintf("failed-checkpoint-%d", i), body, tc.status)
		if f.calls != before+1 || strings.Contains(response, "private SQL") || strings.Contains(response, "durable_checkpoint") {
			t.Fatal(response, f)
		}
	}
}
