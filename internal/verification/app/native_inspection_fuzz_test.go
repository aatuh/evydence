package app_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/application"
	legacydomain "github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var nativeFuzzNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func nativeFuzzJSON(t testing.TB, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("invalid synthetic snapshot", err)
	}
	return string(raw)
}

func nativeFuzzVerdict(inspection verificationapp.SubjectInspection) string {
	return verificationdomain.AggregateVerificationState(inspection.Profile, inspection.Checks).String()
}

// Only the immutable page reader is replaced. Hashing, historical hash rules,
// signing-key policy and Ed25519 verification execute production code. Each
// callback has at most eight one-entry pages and one signed entry.
type nativeFuzzChain struct {
	view  verificationapp.AuditChainVerificationView
	pages []verificationapp.AuditChainVerificationPage
	reads int
}

func (c *nativeFuzzChain) ReadAuditChainVerificationPage(ctx context.Context, view verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	if err := ctx.Err(); err != nil {
		return verificationapp.AuditChainVerificationPage{}, err
	}
	if view != c.view || budget < 0 || c.reads > 8 {
		return verificationapp.AuditChainVerificationPage{}, verificationapp.ErrConflict
	}
	i := c.reads
	if i == 0 && after != nil {
		return verificationapp.AuditChainVerificationPage{}, verificationapp.ErrConflict
	}
	if i > 0 {
		if i > len(c.pages) || len(c.pages[i-1].Entries) != 1 || after == nil || *after != c.pages[i-1].Entries[0].Sequence {
			return verificationapp.AuditChainVerificationPage{}, verificationapp.ErrConflict
		}
	}
	c.reads++
	if i >= len(c.pages) {
		return verificationapp.AuditChainVerificationPage{}, nil
	}
	return c.pages[i], nil
}

func nativeFuzzAudit(t testing.TB, raw []byte, count int, legacy bool) nativeFuzzChain {
	t.Helper()
	c := nativeFuzzChain{view: verificationapp.AuditChainVerificationView{TenantID: "tenant", EntryCount: int64(count), HeadSequence: int64(count)}}
	for i := 0; i < count; i++ {
		e := verificationdomain.AuditChainEntry{
			ID: "entry-" + strconv.Itoa(i), TenantID: "tenant", Sequence: int64(i + 1), EntryType: "test",
			SubjectType: "evidence_item", SubjectID: "evidence", ActorType: "api_key", ActorID: "caller",
			PayloadHash: integrityFuzzDigest(raw), PreviousEntryHash: c.view.HeadHash, OccurredAt: nativeFuzzNow.Add(-time.Minute),
			Metadata: map[string]any{"content": base64.RawStdEncoding.EncodeToString(raw)}, SchemaVersion: verificationdomain.AuditChainEntrySchemaVersion,
		}
		if legacy {
			e.SchemaVersion = verificationapp.AuditChainEntryLegacySchemaVersion
			e.OccurredAt = e.OccurredAt.Add(777 * time.Nanosecond)
		}
		page := verificationapp.AuditChainVerificationPage{BytesRead: 16 << 10}
		if i == count-1 {
			e.SubjectType, e.SubjectID, e.SignatureRef = "release_bundle", "bundle", "signature"
			subject := verificationapp.SubjectReference{TenantID: e.TenantID, Type: e.SubjectType, ID: e.SubjectID}
			page.Signatures, page.Keys = integrityFuzzSigning(t, subject, []byte(e.PayloadHash), nativeFuzzNow)
			page.Bindings = map[string]verificationapp.AuditSignatureBinding{e.ID: {Subject: subject, Payload: e.PayloadHash}}
		}
		if err := verificationapp.RehashAuditChainEntry(&e, integrityFuzzHasher{}); err != nil {
			t.Fatal(err)
		}
		c.view.HeadHash = e.EntryHash
		if legacy {
			// Persisted legacy timestamps lost sub-microsecond precision. The
			// historical recovery path must still verify the recorded hash.
			e.OccurredAt = e.OccurredAt.Truncate(time.Microsecond)
		}
		page.Entries = []verificationdomain.AuditChainEntry{e}
		c.pages = append(c.pages, page)
	}
	return c
}

func (c nativeFuzzChain) inspect(t *testing.T, ctx context.Context) (verificationapp.SubjectInspection, error) {
	t.Helper()
	c.reads = 0
	result, err := verificationapp.InspectAuditChainSnapshot(ctx, &c, c.view, "tenant", nativeFuzzNow, integrityFuzzHasher{}, localed25519.PayloadVerifier{})
	if c.reads > len(c.pages)+1 {
		t.Fatal("unbounded native page reads")
	}
	return result, err
}

func FuzzAuditChainIntegrity(f *testing.F) {
	for mode := uint8(0); mode < 12; mode++ {
		f.Add([]byte("paged synthetic audit"), mode)
	}
	f.Add([]byte{}, uint8(255))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		chain := nativeFuzzAudit(t, raw, 1+int(mode%8), mode&16 != 0)
		before := nativeFuzzJSON(t, chain.pages)
		positive, err := chain.inspect(t, t.Context())
		if err != nil || nativeFuzzVerdict(positive) != "passed" {
			t.Fatalf("signed native chain rejected: %v", err)
		}
		again, err := chain.inspect(t, t.Context())
		if err != nil || !reflect.DeepEqual(positive, again) {
			t.Fatal("native audit inspection is not repeatable")
		}
		changed := nativeFuzzAudit(t, raw, len(chain.pages), mode&16 != 0)
		last := len(changed.pages) - 1
		switch mode % 12 {
		case 0:
			changed.pages[0].Entries[0].PayloadHash += "changed"
		case 1:
			changed.pages[0].Entries[0].TenantID = "foreign"
		case 2:
			changed.pages[0].Entries[0].PreviousEntryHash = "changed"
		case 3:
			changed.pages[last].Signatures[0].Value = integrityFuzzTamperSignature(t, changed.pages[last].Signatures[0].Value)
		case 4:
			binding := changed.pages[last].Bindings[changed.pages[last].Entries[0].ID]
			binding.Subject.ID += "-foreign"
			changed.pages[last].Bindings[changed.pages[last].Entries[0].ID] = binding
		case 5:
			changed.pages[last].Keys[0].TenantID = "foreign"
		case 6:
			changed.pages = changed.pages[:last]
		case 7:
			changed.pages[0].BytesRead = 0
		case 8:
			changed.pages[0].BytesRead = verificationapp.MaxAuditChainVerificationBytes + 1
		case 9:
			changed.pages[0].Entries[0].SchemaVersion = "unknown"
		case 10:
			changed.view.HeadHash = "changed"
		case 11:
			changed.view.TenantID = "foreign"
		}
		decision, err := changed.inspect(t, t.Context())
		if err == nil && nativeFuzzVerdict(decision) == "passed" {
			t.Fatal("changed chain, signature, binding or page passed")
		}
		if nativeFuzzJSON(t, chain.pages) != before {
			t.Fatal("native audit inspector mutated source pages")
		}
		nativeFuzzSnapshotCommandProperty(t, func() *nativeFuzzPorts {
			return &nativeFuzzPorts{nativeFuzzChain: chain}
		}, "audit_chain", "", "passed", mode)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := chain.inspect(t, ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled audit verification continued")
		}
	})
}

// This is the exact canonical field/wire composition used by the production
// evidence canonicalization adapter, rather than a fixed expected hash fake.
type nativeFuzzEvidenceHasher struct{}

func (nativeFuzzEvidenceHasher) HashEvidence(ctx context.Context, item evidencedomain.EvidenceItem) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(legacydomain.EvidenceFromContextModel(evidencedomain.CanonicalEvidenceFields(item)))
}

func FuzzEvidenceCanonicalIntegrity(f *testing.F) {
	for mode := uint8(0); mode < 8; mode++ {
		f.Add([]byte("synthetic evidence"), mode)
	}
	f.Add([]byte{}, uint8(255))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		item := evidencedomain.EvidenceItem{ID: "evidence", TenantID: "tenant", Title: base64.RawStdEncoding.EncodeToString(raw), PayloadHash: integrityFuzzDigest(raw), ReleaseID: "origin", Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion, Metadata: map[string]any{"synthetic": true}}
		if mode&1 != 0 {
			item.Canonicalization = evidencedomain.LegacyEvidenceCanonicalizationProfileVersion
		}
		hasher := nativeFuzzEvidenceHasher{}
		hash, err := hasher.HashEvidence(t.Context(), item)
		if err != nil {
			t.Fatal(err)
		}
		item.CanonicalHash = hash
		snapshot := verificationapp.EvidenceVerificationSnapshot{Subject: verificationapp.SubjectReference{TenantID: "tenant", Type: "evidence_item", ID: "evidence"}, Item: item}
		// Mutable relationship projections have changed since creation. Only
		// the same-tenant/evidence versioned origin may restore legacy inputs.
		snapshot.Item.ReleaseID = "current"
		event := evidencedomain.EvidenceLifecycleEvent{TenantID: "tenant", EvidenceID: "evidence", SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"release_id": "origin"}}}
		snapshot.Lifecycle = []evidencedomain.EvidenceLifecycleEvent{event}
		before := nativeFuzzJSON(t, snapshot)
		inspect := func(s verificationapp.EvidenceVerificationSnapshot) verificationapp.SubjectInspection {
			got, err := verificationapp.InspectEvidenceCanonicalHash(t.Context(), s, hasher)
			if err != nil {
				t.Fatal(err)
			}
			return got
		}
		positive := inspect(snapshot)
		if nativeFuzzVerdict(positive) != "passed" || !reflect.DeepEqual(positive, inspect(snapshot)) {
			t.Fatal("canonical evidence/lifecycle positive is not stable")
		}
		changed := snapshot
		switch mode % 4 {
		case 0:
			changed.Item.Title += "changed"
		case 1:
			changed.Item.TenantID = "foreign"
		case 2:
			changed.Item.PayloadHash += "changed"
		case 3:
			changed.Item.CanonicalHash += "changed"
		}
		if nativeFuzzVerdict(inspect(changed)) == "passed" {
			t.Fatal("changed immutable evidence passed")
		}
		if mode&1 != 0 {
			for _, foreign := range []string{"tenant", "evidence", "schema", "conflict", "malformed"} {
				badEvent := event
				switch foreign {
				case "tenant":
					badEvent.TenantID = "foreign"
				case "evidence":
					badEvent.EvidenceID = "foreign"
				case "schema":
					badEvent.SchemaVersion = "unknown"
				case "conflict":
					badEvent.Details = map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"release_id": "conflicting"}}
				case "malformed":
					badEvent.Details = map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"release_id": 7}}
				}
				changed = snapshot
				changed.Lifecycle = []evidencedomain.EvidenceLifecycleEvent{badEvent}
				if foreign == "conflict" {
					changed.Lifecycle = append(changed.Lifecycle, event)
				}
				if nativeFuzzVerdict(inspect(changed)) == "passed" {
					t.Fatal("invalid canonical origin granted legacy hash authority")
				}
			}
		}
		if nativeFuzzJSON(t, snapshot) != before {
			t.Fatal("evidence inspector mutated source")
		}
		nativeFuzzSnapshotCommandProperty(t, func() *nativeFuzzPorts {
			return &nativeFuzzPorts{subject: snapshot.Subject, evidence: snapshot}
		}, "evidence_item", "evidence", "passed", mode)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := verificationapp.InspectEvidenceCanonicalHash(ctx, snapshot, hasher); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled evidence verification continued")
		}
	})
}

func FuzzArtifactSignatureMetadata(f *testing.F) {
	for mode := uint8(0); mode < 4; mode++ {
		f.Add([]byte("synthetic artifact metadata"), mode)
	}
	f.Add([]byte{}, uint8(255))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		digest := integrityFuzzDigest(raw)
		snapshot := verificationapp.ArtifactSignatureVerificationSnapshot{Subject: verificationapp.SubjectReference{TenantID: "tenant", Type: "artifact_signature", ID: "signature", Resources: application.ResourceReferences{ArtifactID: "artifact"}}, ArtifactDigest: digest, SignatureDigest: digest, AlgorithmPresent: true, SignaturePresent: true}
		before := snapshot
		positive := verificationapp.InspectArtifactSignatureMetadata(snapshot)
		if nativeFuzzVerdict(positive) != verificationdomain.VerificationStateLimited || positive.Profile.TransparencyProof != "not_evaluated" || !reflect.DeepEqual(positive, verificationapp.InspectArtifactSignatureMetadata(snapshot)) {
			t.Fatal("metadata-only profile acquired cryptographic assurance or changed on repeat")
		}
		changed := snapshot
		switch mode % 4 {
		case 0:
			changed.ArtifactDigest += "changed"
		case 1:
			changed.SignatureDigest += "changed"
		case 2:
			changed.AlgorithmPresent = false
		case 3:
			changed.SignaturePresent = false
		}
		if nativeFuzzVerdict(verificationapp.InspectArtifactSignatureMetadata(changed)) != "failed" {
			t.Fatal("inconsistent or absent metadata did not fail")
		}
		if snapshot != before {
			t.Fatal("metadata inspection mutated input")
		}
		nativeFuzzSnapshotCommandProperty(t, func() *nativeFuzzPorts {
			return &nativeFuzzPorts{subject: snapshot.Subject, artifact: snapshot}
		}, "artifact_signature", "signature", verificationdomain.VerificationStateLimited, mode)
	})
}

func FuzzBackupManifestRecordedChecks(f *testing.F) {
	for mode := uint8(0); mode < 9; mode++ {
		f.Add([]byte("synthetic backup state"), mode)
	}
	f.Add([]byte{}, uint8(255))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		snapshot := verificationapp.BackupVerificationSnapshot{Subject: verificationapp.SubjectReference{TenantID: "tenant", Type: "backup_manifest", ID: "backup"}, StateHash: integrityFuzzDigest(raw), Checks: []verificationdomain.VerifyCheck{{Name: "state_count", Result: "passed", Detail: "synthetic recorded consistency only"}}}
		before := nativeFuzzJSON(t, snapshot)
		positive, err := verificationapp.InspectBackupManifestRecordedChecks(snapshot)
		if err != nil || nativeFuzzVerdict(positive) != "passed" || len(positive.Profile.Limitations) == 0 {
			t.Fatalf("recorded manifest rejected: %v", err)
		}
		again, err := verificationapp.InspectBackupManifestRecordedChecks(snapshot)
		if err != nil || !reflect.DeepEqual(positive, again) {
			t.Fatal("backup inspection is not stable")
		}
		changed := snapshot
		changed.Checks = append([]verificationdomain.VerifyCheck(nil), snapshot.Checks...)
		expected := ""
		switch mode % 9 {
		case 0:
			changed.Checks[0].Result, expected = "failed", "failed"
		case 1:
			changed.Checks[0].Result, expected = "error", "error"
		case 2:
			changed.Checks[0].Result, expected = "unknown", verificationdomain.VerificationStateLimited
		case 3:
			changed.Subject.Type = "foreign"
		case 4:
			changed.Subject.TenantID = ""
		case 5:
			changed.Subject.Resources.ProductID = "unexpected"
		case 6:
			changed.Checks[0].Name = "bad\x00name"
		case 7:
			changed.StateHash = ""
		case 8:
			changed.Checks = make([]verificationdomain.VerifyCheck, verificationapp.MaxBackupVerificationChecks+1)
		}
		decision, err := verificationapp.InspectBackupManifestRecordedChecks(changed)
		if expected == "" {
			if !errors.Is(err, verificationapp.ErrConflict) {
				t.Fatal("invalid backup manifest accepted")
			}
		} else if err != nil || nativeFuzzVerdict(decision) != expected {
			t.Fatal("recorded failure/error/unknown result acquired a pass")
		}
		// Returned checks are owned by the result, not the immutable source.
		positive.Checks[0].Detail = "changed output"
		if nativeFuzzJSON(t, snapshot) != before {
			t.Fatal("backup inspection or output mutation changed source")
		}
		nativeFuzzSnapshotCommandProperty(t, func() *nativeFuzzPorts {
			return &nativeFuzzPorts{subject: snapshot.Subject, backup: snapshot}
		}, "backup_manifest", "backup", "passed", mode)
	})
}
