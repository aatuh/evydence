package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

type workerFuzzParserCase struct {
	kind uint8
	file string
	raw  []byte
}

func workerFuzzParse(ctx context.Context, kind uint8, raw []byte) (any, error) {
	switch kind {
	case 0:
		return parseReplayedSBOM(raw, 64<<10, app.ParserVersionCycloneDXJSON)
	case 1:
		return parseReplayedSBOM(raw, 64<<10, app.ParserVersionSPDXJSON)
	case 2:
		return parseReplayedVulnerabilityScan(raw, "scan", 64<<10)
	case 3, 4:
		return parseReplayedVEX(raw, 64<<10)
	case 5:
		return parseReplayedOpenAPIContract(ctx, raw)
	case 6:
		return parseReplayedAttestation(raw)
	default:
		return nil, errors.New("unknown synthetic worker parser family")
	}
}

// These are recorded-metadata consistency verifiers. Signature and external
// provider assurance remain in the separate native cryptographic profiles.
func workerFuzzVerify(raw []byte, value any, changed bool) error {
	switch parsed := value.(type) {
	case replayedSBOM:
		stored := domain.SBOM{SpecVersion: parsed.SpecVersion, ComponentCount: parsed.ComponentCount, Components: append([]domain.SBOMComponent(nil), parsed.Components...)}
		if changed {
			stored.SpecVersion += "changed"
		}
		return verifyReplayedSBOM(parsed, stored)
	case replayedVulnerabilityScan:
		stored := domain.VulnerabilityScan{Scanner: parsed.Scanner, TargetRef: parsed.TargetRef, Adapter: parsed.Adapter, AdapterVersion: parsed.AdapterVersion, SourceSchema: parsed.SourceSchema, Summary: parsed.Summary}
		if changed {
			stored.Scanner += "changed"
		}
		return verifyReplayedVulnerabilityScan(parsed, stored)
	case replayedVEX:
		stored := domain.VEXDocument{Format: parsed.Format, Author: parsed.Author, StatementCount: parsed.StatementCount, StatusSummary: parsed.StatusSummary}
		version := app.ParserVersionOpenVEXJSON
		if parsed.Format == "cyclonedx" {
			version = app.ParserVersionCycloneDXVEXJSON
		}
		if err := requireVEXParserFormat(postgres.ClaimedJob{Payload: map[string]any{"parser_version": version}}, stored.Format, parsed.Format); err != nil {
			return err
		}
		if changed {
			stored.Format += "changed"
		}
		return verifyReplayedVEX(parsed, stored)
	case replayedOpenAPIContract:
		stored := domain.OpenAPIContract{PathCount: parsed.PathCount, Hash: digestBytes(raw)}
		if changed {
			stored.Hash += "changed"
		}
		return verifyReplayedOpenAPIContract(raw, parsed, stored)
	case replayedAttestation:
		stored := domain.BuildAttestation{PayloadHash: digestBytes(raw), PredicateType: parsed.PredicateType, SubjectDigests: append([]string(nil), parsed.SubjectDigests...)}
		if changed {
			stored.PayloadHash += "changed"
		}
		return verifyReplayedAttestation(raw, parsed, stored)
	default:
		return errors.New("missing worker verification property")
	}
}

// One finalized lifecycle row and one bounded object stand in for storage.
// The read-only verifier must never use a mutation or an unbounded read.
type workerFuzzLifecycle struct {
	payload app.ObjectPayload
	reads   int
	writes  int
}

func (s *workerFuzzLifecycle) GetObjectPayload(ctx context.Context, tenant, digest string) (app.ObjectPayload, error) {
	if err := ctx.Err(); err != nil {
		return app.ObjectPayload{}, err
	}
	s.reads++
	if tenant != s.payload.TenantID || digest != s.payload.Digest {
		return app.ObjectPayload{}, app.ErrNotFound
	}
	return s.payload, nil
}
func (s *workerFuzzLifecycle) MarkObjectPayloadFinalized(context.Context, app.ObjectPayload) error {
	s.writes++
	return app.ErrConflict
}
func (s *workerFuzzLifecycle) MarkObjectPayloadFailed(context.Context, app.ObjectPayload, string) error {
	s.writes++
	return app.ErrConflict
}
func (s *workerFuzzLifecycle) MarkObjectPayloadOrphaned(context.Context, app.ObjectPayload) error {
	s.writes++
	return app.ErrConflict
}

func workerFuzzObjectBinding(t *testing.T, raw []byte, mode uint8) {
	t.Helper()
	digest := digestBytes(raw)
	_, key, err := app.CanonicalObjectPayloadKeys("tenant", digest)
	if err != nil {
		t.Fatal(err)
	}
	fixture := func() (*workerFuzzLifecycle, *nativeBoundedReadFake, postgres.ClaimedJob) {
		state := &workerFuzzLifecycle{payload: app.ObjectPayload{TenantID: "tenant", Digest: digest, FinalKey: key, Status: app.ObjectPayloadFinalized}}
		objects := &nativeBoundedReadFake{object: app.Object{Key: key, TenantID: "tenant", Digest: digest, Bytes: append([]byte(nil), raw...)}}
		job := postgres.ClaimedJob{TenantID: "tenant", Payload: map[string]any{"payload_ref": "object://" + key, "payload_hash": digest, "payload_digest": digest, "payload_lifecycle": app.PayloadLifecycleVersion}}
		return state, objects, job
	}
	state, objects, job := fixture()
	value, ok, err := verifyJobObject(t.Context(), state, objects, job, 64<<10)
	if err != nil || !ok || !bytes.Equal(value.Bytes, raw) || objects.gets != 0 || objects.bounded != 1 || objects.limit != 64<<10 || state.reads != 1 || state.writes != 0 {
		t.Fatal("worker failed finalized bounded object binding", err)
	}
	state, objects, job = fixture()
	ctx := t.Context()
	switch mode % 8 {
	case 0:
		job.Payload["payload_ref"] = "object://tenants/foreign/payload"
	case 1:
		state.payload.Status = app.ObjectPayloadStaged
	case 2:
		objects.object.TenantID = "foreign"
	case 3:
		objects.object.Digest += "changed"
	case 4:
		objects.object.Bytes[0] ^= 1
	case 5:
		job.Payload["payload_hash"] = digest + "changed"
	case 6:
		objects.err = app.ErrConflict
	case 7:
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		cancel()
	}
	if _, ok, err := verifyJobObject(ctx, state, objects, job, 64<<10); err == nil || ok || state.writes != 0 || objects.gets != 0 {
		t.Fatal("unbound, unfinalized, rejected or canceled worker object passed")
	}
	if (mode%8 <= 1 || mode%8 == 7) && objects.bounded != 0 {
		t.Fatal("worker read object bytes before validating scope and lifecycle")
	}
}

func FuzzWorkerEvidenceParsers(f *testing.F) {
	attestation, statement := workerFuzzDSSE(f)
	cases := []workerFuzzParserCase{
		{kind: 0, file: "../../internal/app/parsers/cyclonedx/testdata/official/valid-dependency-1.6.json"},
		{kind: 1, file: "../../internal/app/parsers/spdx/testdata/spdx-2.3-example.json"},
		{kind: 2, file: "../../internal/app/parsers/scanners/testdata/generic.json"},
		{kind: 3, file: "../../internal/app/parsers/vex/testdata/openvex/openvex-spec-minimal.json"},
		{kind: 4, file: "../../internal/app/parsers/vex/testdata/cyclonedx-vex/official-vex-1.4.json"},
		{kind: 5, raw: []byte(fuzzWorkerOpenAPIDocument)},
		{kind: 6, raw: attestation},
	}
	for i := range cases {
		c := &cases[i]
		if c.file != "" {
			var err error
			c.raw, err = os.ReadFile(c.file)
			if err != nil {
				f.Fatal(err)
			}
		}
		for mode := uint8(0); mode < 8; mode++ {
			f.Add(c.raw, c.kind, mode)
		}
	}
	f.Add(append([]byte(`{"payloadType":"application/vnd.in-toto+json",`), attestation[1:]...), uint8(6), uint8(0))
	f.Add(append([]byte(`{"payload\u0054ype":"application/vnd.in-toto+json",`), attestation[1:]...), uint8(6), uint8(1))
	var envelope map[string]any
	if err := json.Unmarshal(attestation, &envelope); err != nil {
		f.Fatal(err)
	}
	envelope["payload"] = base64.StdEncoding.EncodeToString(append([]byte(`{"_type":"https://in-toto.io/Statement/v1",`), statement[1:]...))
	duplicateStatement, err := json.Marshal(envelope)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(duplicateStatement, uint8(6), uint8(2))
	f.Add([]byte(`{}`), uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, family, mode uint8) {
		if len(raw) > 64<<10 {
			return
		}
		limits := jsonbounds.Limits{MaxDepth: 24, MaxObjectKeys: 128, MaxArrayItems: 128, MaxStringBytes: 32 << 10}
		shapeErr := jsonbounds.Validate(raw, limits)
		if shapeErr != nil && !errors.Is(shapeErr, jsonbounds.ErrDuplicateObjectKey) {
			return
		}
		c := cases[int(family)%len(cases)]
		if c.kind == 6 {
			var envelope struct {
				Payload string `json:"payload"`
			}
			if json.Unmarshal(raw, &envelope) == nil {
				decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
				if err == nil && json.Valid(decoded) {
					decodedErr := jsonbounds.Validate(decoded, limits)
					if decodedErr != nil && !errors.Is(decodedErr, jsonbounds.ErrDuplicateObjectKey) {
						return
					}
					if decodedErr != nil {
						shapeErr = decodedErr
					}
				}
			}
		}
		before := append([]byte(nil), raw...)
		first, err := workerFuzzParse(t.Context(), c.kind, raw)
		again, againErr := workerFuzzParse(t.Context(), c.kind, raw)
		if (err == nil) != (againErr == nil) || !reflect.DeepEqual(first, again) || !bytes.Equal(raw, before) {
			t.Fatal("worker interpretation is not repeatable or mutated its source")
		}
		if err != nil {
			if !reflect.DeepEqual(first, reflect.Zero(reflect.TypeOf(first)).Interface()) {
				t.Fatal("invalid worker input leaked a partial interpretation")
			}
		} else if shapeErr != nil || workerFuzzVerify(raw, first, false) != nil || workerFuzzVerify(raw, first, true) == nil {
			t.Fatal("worker accepted ambiguous input or lost recorded-metadata binding")
		}
		positive, err := workerFuzzParse(t.Context(), c.kind, c.raw)
		if err != nil || workerFuzzVerify(c.raw, positive, false) != nil || workerFuzzVerify(c.raw, positive, true) == nil {
			t.Fatal("known worker projection lost its positive or controlled-tamper behavior", err)
		}
		workerFuzzObjectBinding(t, c.raw, mode)
	})
}
