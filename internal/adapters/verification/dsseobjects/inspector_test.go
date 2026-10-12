package dsseobjects

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	securedsse "github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type payloadReaderFake struct {
	object app.Object
	err    error
	calls  int
	limit  int64
}

func (f *payloadReaderFake) GetBounded(_ context.Context, key string, limit int64) (app.Object, error) {
	f.calls++
	f.limit = limit
	return f.object, f.err
}

func dsseObjectFixture(t *testing.T) (Inspector, verificationapp.DSSEVerificationSnapshot, *payloadReaderFake) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile("../../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []map[string]string{{"keyid": "root-1", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, securedsse.PAE("application/vnd.in-toto+json", payload)))}}})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	_, key, err := app.CanonicalObjectPayloadKeys("tenant", hash)
	if err != nil {
		t.Fatal(err)
	}
	reader := &payloadReaderFake{object: app.Object{Key: key, TenantID: "tenant", MediaType: "application/vnd.dsse.envelope+json", Digest: hash, Bytes: raw}}
	snapshot := verificationapp.DSSEVerificationSnapshot{Subject: verificationapp.SubjectReference{TenantID: "tenant"}, PayloadRef: "object://" + key, PayloadHash: hash, PayloadSize: int64(len(raw)), PayloadMediaType: reader.object.MediaType, PayloadFinalized: true, ExpectedSubjectDigests: []string{"sha256:" + strings.Repeat("a", 64)}, Roots: []verificationdomain.DSSETrustRoot{{ID: "root", TenantID: "tenant", Name: "Root", KeyID: "root-1", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(public), Status: "active", SchemaVersion: verificationdomain.DSSETrustRootSchemaVersion, CreatedAt: time.Now().UTC(), AllowedPredicateTypes: []string{"https://slsa.dev/provenance/v1"}, ExpectedBuilderIDs: []string{"https://github.com/actions/runner"}, RequiredClaims: []string{"builder_id", "build_type", "external_parameters"}}}}
	return Inspector{Objects: reader}, snapshot, reader
}
func TestDSSEObjectInspectorUsesBoundedReadsAndChecksEveryPayloadBinding(t *testing.T) {
	i, s, reader := dsseObjectFixture(t)
	facts, err := i.VerifyDSSE(t.Context(), s)
	if err != nil || len(facts.Checks) != 7 || len(facts.AcceptedRootIDs) != 1 || facts.AcceptedRootIDs[0] != "root" || reader.limit != s.PayloadSize {
		t.Fatal(facts, err, reader.limit)
	}
	for _, change := range []struct {
		name string
		edit func(*app.Object)
	}{
		{"tenant", func(o *app.Object) { o.TenantID = "foreign" }},
		{"key", func(o *app.Object) { o.Key = "tenants/foreign/payload" }},
		{"digest", func(o *app.Object) { o.Digest = "sha256:" + strings.Repeat("b", 64) }},
		{"size", func(o *app.Object) { o.Bytes = append(o.Bytes, ' ') }},
		{"bytes", func(o *app.Object) { o.Bytes[0] = 'x' }},
		{"media", func(o *app.Object) { o.MediaType = "text/plain" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			i, s, reader := dsseObjectFixture(t)
			change.edit(&reader.object)
			facts, err := i.VerifyDSSE(t.Context(), s)
			if !errors.Is(err, verificationapp.ErrValidation) || len(facts.Checks) != 0 {
				t.Fatal("invalid object assigned trust", facts, err)
			}
		})
	}
	for _, edit := range []func(*verificationapp.DSSEVerificationSnapshot){func(s *verificationapp.DSSEVerificationSnapshot) { s.PayloadRef = "object://tenants/foreign/payload" }, func(s *verificationapp.DSSEVerificationSnapshot) {
		s.PayloadSize = verificationapp.MaxDSSEPayloadBytes + 1
	}, func(s *verificationapp.DSSEVerificationSnapshot) { s.PayloadFinalized = false }} {
		i, s, reader := dsseObjectFixture(t)
		edit(&s)
		if _, err := i.VerifyDSSE(t.Context(), s); !errors.Is(err, verificationapp.ErrValidation) || reader.calls != 0 {
			t.Fatal("unsafe reference read", err)
		}
	}
	for _, test := range []struct{ source, target error }{{app.ErrConflict, verificationapp.ErrConflict}, {app.ErrValidation, verificationapp.ErrValidation}, {app.ErrNotFound, verificationapp.ErrNotFound}, {context.Canceled, context.Canceled}} {
		i, s, reader := dsseObjectFixture(t)
		reader.err = test.source
		if _, err := i.VerifyDSSE(t.Context(), s); !errors.Is(err, test.target) {
			t.Fatal("storage error mapping", err)
		}
	}
}

func TestDSSEObjectInspectorRejectsForeignPoliciesBeforeObjectRead(t *testing.T) {
	i, snapshot, reader := dsseObjectFixture(t)
	snapshot.Roots[0].TenantID = "foreign"
	if _, err := i.VerifyDSSE(t.Context(), snapshot); !errors.Is(err, verificationapp.ErrConflict) || reader.calls != 0 {
		t.Fatal("foreign root policy triggered a payload read", err)
	}
}
