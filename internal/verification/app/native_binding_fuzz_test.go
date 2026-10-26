package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	securedsse "github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/aatuh/evydence/internal/adapters/verification/cosignobjects"
	"github.com/aatuh/evydence/internal/adapters/verification/dsseobjects"
	"github.com/aatuh/evydence/internal/adapters/verification/sigstore"
	legacyapp "github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type nativeFuzzObject struct {
	object legacyapp.Object
	reads  int
}

func (o *nativeFuzzObject) GetBounded(ctx context.Context, key string, limit int64) (legacyapp.Object, error) {
	if err := ctx.Err(); err != nil {
		return legacyapp.Object{}, err
	}
	if limit < 1 || limit > 64<<10 || int64(len(o.object.Bytes)) > limit || o.reads >= 4 {
		return legacyapp.Object{}, legacyapp.ErrValidation
	}
	o.reads++
	return o.object, nil
}

func nativeFuzzObjectFor(t testing.TB, body []byte, media string) *nativeFuzzObject {
	t.Helper()
	digest := integrityFuzzDigest(body)
	_, key, err := legacyapp.CanonicalObjectPayloadKeys("tenant", digest)
	if err != nil {
		t.Fatal(err)
	}
	return &nativeFuzzObject{object: legacyapp.Object{Key: key, TenantID: "tenant", Digest: digest, MediaType: media, Bytes: append([]byte(nil), body...)}}
}

func nativeFuzzChangedDigest(raw []byte, original string) string {
	candidate := integrityFuzzDigest(raw)
	if candidate == original {
		// A fuzzer can supply the original artifact bytes. The negative
		// oracle must still change the digest in that case.
		last := "0"
		if candidate[len(candidate)-1] == '0' {
			last = "1"
		}
		candidate = candidate[:len(candidate)-1] + last
	}
	return candidate
}

func nativeFuzzDSSE(t testing.TB, raw []byte) (*nativeFuzzPorts, *nativeFuzzObject) {
	t.Helper()
	// Synthetic SLSA v1 content uses the same required claims as the pinned
	// in-toto fixture. No ambient identity, random key or provider is used.
	payload := []byte(nativeFuzzJSON(t, map[string]any{
		"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1",
		"subject": []any{map[string]any{"name": "synthetic.tar.gz", "digest": map[string]string{"sha256": strings.Repeat("a", 64)}}},
		"predicate": map[string]any{
			"buildDefinition": map[string]any{"buildType": "https://github.com/actions/workflow", "externalParameters": map[string]string{"content": base64.RawStdEncoding.EncodeToString(raw)}},
			"runDetails":      map[string]any{"builder": map[string]string{"id": "https://builder.example.invalid/synthetic"}},
		},
	}))
	seed := sha256.Sum256([]byte("Evydence EVY-1111 synthetic DSSE key"))
	private := ed25519.NewKeyFromSeed(seed[:])
	envelope := []byte(nativeFuzzJSON(t, map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []map[string]string{{"keyid": "root-key", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(private, securedsse.PAE("application/vnd.in-toto+json", payload)))}}}))
	o := nativeFuzzObjectFor(t, envelope, "application/vnd.dsse.envelope+json")
	s := &nativeFuzzPorts{subject: verificationapp.SubjectReference{TenantID: "tenant", Type: "build_attestation", ID: "attestation", Resources: application.ResourceReferences{BuildID: "build"}}}
	s.dsse = verificationapp.DSSEVerificationSnapshot{Subject: s.subject, EvidenceID: "evidence", PayloadRef: "object://" + o.object.Key, PayloadHash: o.object.Digest, PayloadSize: int64(len(envelope)), PayloadMediaType: o.object.MediaType, PayloadFinalized: true, ExpectedSubjectDigests: []string{"sha256:" + strings.Repeat("a", 64)}, Roots: []verificationdomain.DSSETrustRoot{{ID: "root", TenantID: "tenant", Name: "Synthetic root", KeyID: "root-key", Algorithm: "Ed25519", PublicKey: base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), Status: "active", SchemaVersion: verificationdomain.DSSETrustRootSchemaVersion, CreatedAt: nativeFuzzNow, AllowedPredicateTypes: []string{"https://slsa.dev/provenance/v1"}, ExpectedBuilderIDs: []string{"https://builder.example.invalid/synthetic"}, RequiredClaims: []string{"builder_id", "build_type", "external_parameters"}}}}
	return s, o
}

func nativeFuzzRunDSSE(t *testing.T, s *nativeFuzzPorts, object *nativeFuzzObject, actorTenant string) (verificationdomain.VerificationResult, error) {
	t.Helper()
	c, err := verificationapp.NewDSSEVerificationCommands(verificationapp.DSSEVerificationConfig{Transactions: s, Authorizer: s, Verifier: dsseobjects.Inspector{Objects: object}, Clock: application.ClockFunc(func() time.Time { return nativeFuzzNow }), IDs: nativeFuzzIDs()})
	if err != nil {
		t.Fatal(err)
	}
	actor := nativeFuzzActor()
	actor.TenantID = actorTenant
	return c.VerifyDSSEAttestationSignature(t.Context(), actor, "attestation")
}

func FuzzDSSESnapshotBinding(f *testing.F) {
	for mode := uint8(0); mode < 14; mode++ {
		f.Add([]byte("native DSSE snapshot"), mode)
	}
	f.Add([]byte{}, uint8(255))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		s, object := nativeFuzzDSSE(t, raw)
		before := nativeFuzzJSON(t, []any{s.dsse, object.object})
		positive, err := nativeFuzzRunDSSE(t, s, object, "tenant")
		if err != nil || object.reads != 1 {
			t.Fatalf("native signed DSSE rejected or object not read once: %v", err)
		}
		nativeFuzzAssertReceipt(t, s, positive, "build_attestation", "attestation", "passed")
		againState, againObject := nativeFuzzDSSE(t, raw)
		again, err := nativeFuzzRunDSSE(t, againState, againObject, "tenant")
		if err != nil || !reflect.DeepEqual(positive, again) {
			t.Fatal("native DSSE receipt is not repeatable")
		}
		changed, changedObject := nativeFuzzDSSE(t, raw)
		switch mode % 14 {
		case 0:
			changed.subject.TenantID = "foreign"
		case 1:
			changed.dsse.Subject.ID = "other"
		case 2:
			changed.dsse.Roots[0].TenantID = "foreign"
		case 3:
			changed.dsse.PayloadFinalized = false
		case 4:
			changed.dsse.PayloadRef = "object://tenants/foreign/payload"
		case 5:
			changedObject.object.TenantID = "foreign"
		case 6:
			changedObject.object.Key += "-other"
		case 7:
			changedObject.object.Digest = integrityFuzzDigest([]byte("different"))
		case 8:
			changedObject.object.MediaType = "text/plain"
		case 9:
			changedObject.object.Bytes[0] ^= 1
		case 10:
			changed.dsse.ExpectedSubjectDigests = []string{integrityFuzzDigest([]byte("different"))}
		case 11:
			changed.dsse.Roots[0].ExpectedBuilderIDs = []string{"https://other.example.invalid"}
		case 12:
			changed.dsse.Roots[0].PublicKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
		case 13:
			changed.dsse.PayloadSize = verificationapp.MaxDSSEPayloadBytes + 1
		}
		decision, err := nativeFuzzRunDSSE(t, changed, changedObject, "tenant")
		if err == nil || decision.Result.String() == "passed" {
			t.Fatal("changed native DSSE binding/policy passed")
		}
		if errors.Is(err, verificationapp.ErrVerificationFailed) {
			nativeFuzzAssertReceipt(t, changed, decision, "build_attestation", "attestation", "failed")
		} else {
			nativeFuzzAssertNoWrites(t, changed)
		}
		if mode%14 <= 4 || mode%14 == 13 {
			if changedObject.reads != 0 {
				t.Fatal("invalid snapshot/root/reference triggered an object read")
			}
		}
		if nativeFuzzJSON(t, []any{s.dsse, object.object}) != before {
			t.Fatal("DSSE command mutated source snapshot or object")
		}
		foreign, foreignObject := nativeFuzzDSSE(t, raw)
		if _, err := nativeFuzzRunDSSE(t, foreign, foreignObject, "foreign"); !errors.Is(err, verificationapp.ErrNotFound) || foreignObject.reads+foreign.payloads != 0 {
			t.Fatal("foreign actor read native DSSE payload")
		}
		nativeFuzzAssertNoWrites(t, foreign)
	})
}

func FuzzCosignSnapshotBinding(f *testing.F) {
	// Existing pinned public upstream fixtures and local roots establish a real
	// offline positive vector. The native owner must preserve every binding.
	trusted, err := os.ReadFile("../../adapters/verification/sigstore/testdata/official-scaffolding.trusted-root.json")
	if err != nil {
		f.Fatal(err)
	}
	baseline, err := os.ReadFile("../../adapters/verification/sigstore/testdata/official-othername.bundle.json")
	if err != nil {
		f.Fatal(err)
	}
	verifier, err := sigstore.New(sigstore.Config{TrustedRootJSON: trusted, TrustRootVersion: "sigstore-go-scaffolding-1"})
	if err != nil {
		f.Fatal(err)
	}
	for mode := uint8(0); mode < 14; mode++ {
		f.Add([]byte("native Cosign snapshot"), mode)
	}
	f.Add([]byte{}, uint8(255))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		const digest = "sha256:bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"
		id := "signature-" + base64.RawURLEncoding.EncodeToString(raw[:min(len(raw), 256)])
		input := verificationapp.VerifyCosignInput{ArtifactSignatureID: id, ExpectedIdentity: "foo!oidc.local", ExpectedIssuer: "http://oidc.local:8080", Mode: verificationapp.CosignVerificationModeKeyless, Offline: true}
		fixture := func() (*nativeFuzzPorts, *nativeFuzzObject) {
			o := nativeFuzzObjectFor(t, baseline, "application/vnd.dev.sigstore.bundle+json;version=0.3")
			s := &nativeFuzzPorts{authorizer: verificationquery.NewCosignVerificationAuthorizer()}
			s.cosign = verificationapp.CosignSnapshot{Subject: verificationapp.CosignSubject{TenantID: "tenant", ArtifactID: "artifact", ArtifactSignatureID: id, SubjectDigest: digest, Resources: application.ResourceReferences{ArtifactID: "artifact"}}, ArtifactDigest: digest, Algorithm: "cosign", PayloadRef: "object://" + o.object.Key, PayloadHash: o.object.Digest, PayloadSize: int64(len(baseline)), PayloadMediaType: o.object.MediaType, PayloadFinalized: true}
			return s, o
		}
		run := func(s *nativeFuzzPorts, o *nativeFuzzObject, actorTenant string, request verificationapp.VerifyCosignInput) (verificationdomain.CosignVerification, error) {
			c, err := verificationapp.NewCosignVerificationCommands(verificationapp.CosignVerificationConfig{Transactions: s, Authorizer: s, Inspector: cosignobjects.Inspector{Objects: o, Verifier: verifier}, Clock: application.ClockFunc(func() time.Time { return nativeFuzzNow }), IDs: nativeFuzzIDs()})
			if err != nil {
				t.Fatal(err)
			}
			actor := nativeFuzzActor()
			actor.TenantID = actorTenant
			return c.VerifyCosign(t.Context(), actor, request)
		}
		s, object := fixture()
		before := nativeFuzzJSON(t, []any{s.cosign, object.object})
		positive, err := run(s, object, "tenant", input)
		if err != nil || positive.Result != "passed" || positive.ArtifactSignatureID != id || positive.SubjectDigest != digest || positive.CertificateIdentity != input.ExpectedIdentity || positive.CertificateIssuer != input.ExpectedIssuer || len(s.results) != 1 || len(s.cosigns) != 1 || len(s.audits) != 1 || len(s.jobs) != 0 || s.results[0].ID != positive.ID || object.reads != 1 {
			t.Fatalf("real native offline Cosign receipt rejected: %v", err)
		}
		againState, againObject := fixture()
		again, err := run(againState, againObject, "tenant", input)
		if err != nil || !reflect.DeepEqual(positive, again) {
			t.Fatal("native Cosign receipt is not stable")
		}
		changed, changedObject := fixture()
		request := input
		switch mode % 14 {
		case 0:
			changed.cosign.Subject.TenantID = "foreign"
		case 1:
			changed.cosign.ArtifactDigest = nativeFuzzChangedDigest(raw, digest)
		case 2:
			changed.cosign.PayloadFinalized = false
		case 3:
			changed.cosign.PayloadRef = "object://tenants/foreign/payload"
		case 4:
			changedObject.object.TenantID = "foreign"
		case 5:
			changedObject.object.Digest = nativeFuzzChangedDigest(raw, object.object.Digest)
		case 6:
			changedObject.object.Bytes[0] ^= 1
		case 7:
			changedObject.object.MediaType = "text/plain"
		case 8:
			request.ExpectedIdentity = "https://different.example.invalid/" + base64.RawURLEncoding.EncodeToString(raw)
		case 9:
			request.ExpectedIssuer = "https://different.example.invalid"
		case 10:
			request.Offline = false
		case 11:
			changed.cosign.Subject.Resources.ReleaseID = "unexpected"
		case 12:
			changed.cosign.PayloadSize = verificationapp.MaxCosignPayloadBytes + 1
		case 13:
			changed.cosign.Algorithm = "metadata-only"
		}
		decision, err := run(changed, changedObject, "tenant", request)
		if err == nil || decision.Result == "passed" {
			t.Fatal("changed native Cosign snapshot, trust policy or online-required request passed")
		}
		if decision.ID == "" {
			nativeFuzzAssertNoWrites(t, changed)
		} else if len(changed.results) != 1 || len(changed.cosigns) != 1 || len(changed.audits) != 1 || changed.results[0].Result.String() == "passed" || changed.cosigns[0].Result == "passed" {
			t.Fatal("failed native Cosign receipt acquired a pass or lost atomic effects")
		}
		if mode%14 <= 3 || mode%14 >= 10 {
			if changedObject.reads != 0 {
				t.Fatal("invalid native Cosign scope/reference triggered an object read")
			}
		}
		if nativeFuzzJSON(t, []any{s.cosign, object.object}) != before {
			t.Fatal("Cosign command mutated source snapshot or bundle")
		}
		foreign, foreignObject := fixture()
		if _, err := run(foreign, foreignObject, "foreign", input); !errors.Is(err, verificationapp.ErrNotFound) || foreign.payloads+foreignObject.reads != 0 {
			t.Fatal("foreign actor read native Cosign payload")
		}
		nativeFuzzAssertNoWrites(t, foreign)
		failed, failedObject := fixture()
		failed.fail = []string{"cosign", "result", "audit", "commit"}[mode%4]
		if _, err := run(failed, failedObject, "tenant", input); !errors.Is(err, errNativeFuzzWrite) {
			t.Fatal("native Cosign receipt failure was not returned")
		}
		nativeFuzzAssertNoWrites(t, failed)
	})
}
