package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type buildAttestationHTTPFake struct {
	calls   int
	buildID string
	raw     []byte
	err     error
}

func (f *buildAttestationHTTPFake) UploadBuildAttestation(_ context.Context, a identitydomain.Actor, id string, raw []byte) (releasedomain.BuildAttestation, error) {
	f.calls++
	f.buildID = id
	f.raw = append([]byte(nil), raw...)
	return releasedomain.BuildAttestation{ID: "durable_attestation", TenantID: a.TenantID, BuildID: id, EvidenceID: "durable_evidence", PayloadHash: "sha256:payload", VerificationStatus: "structurally_valid", SubjectDigests: []string{"sha256:artifact"}, SignatureCount: 1, SchemaVersion: releasedomain.BuildAttestationSchemaVersion}, f.err
}
func TestBuildAttestationHTTPUsesDurableCommandAndReplayWithoutLedgerBuild(t *testing.T) {
	local, secret := testServer(t)
	f := &buildAttestationHTTPFake{}
	s, err := NewServerWithOptions(local.ledger, ServerOptions{BuildAttestationCommands: f})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"YWJj","signatures":[{"sig":"recorded"}]}`)
	path := "/v1/builds/not-in-ledger/attestations"
	body := postRaw(t, s, secret, path, "attestation-replay", raw, 201)
	if f.calls != 1 || f.buildID != "not-in-ledger" || string(f.raw) != string(raw) || !strings.Contains(body, `"id":"durable_attestation"`) || !strings.Contains(body, `"evidence_id":"durable_evidence"`) || !strings.Contains(body, `"subject_digests":["sha256:artifact"]`) {
		t.Fatal(body, f)
	}
	if again := postRaw(t, s, secret, path, "attestation-replay", raw, 201); again != body || f.calls != 1 {
		t.Fatal("replay reran ingestion", again, f)
	}
	postRaw(t, s, secret, path, "attestation-replay", append(raw, ' '), 409)
	for i, tc := range []struct {
		err    error
		status int
	}{{releaseapp.ErrValidation, 400}, {releaseapp.ErrNotFound, 404}, {releaseapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {errors.New("private SQL or object-store error"), 500}} {
		f.err = tc.err
		body := postRaw(t, s, secret, path, fmt.Sprintf("failed-attestation-%d", i), raw, tc.status)
		if strings.Contains(body, "private SQL") || strings.Contains(body, "durable_attestation") {
			t.Fatal("failure leaked result or backend detail", body)
		}
	}
}
