package app

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type releaseManifestCheckpointFake struct{ auditVerificationFake }

func (f *releaseManifestCheckpointFake) ExecuteReleaseManifestCheckpointVerification(ctx context.Context, fn func(context.Context, ReleaseManifestCheckpointTransaction) error) error {
	copy := *f
	copy.results, copy.audits, copy.jobs = nil, nil, nil
	copy.pageReads, copy.budgets = 0, nil
	err := fn(ctx, &copy)
	f.payloadReads, f.pageReads = copy.payloadReads, copy.pageReads
	if err != nil {
		return err
	}
	if f.fail == "commit" {
		return errVerificationTestFailure
	}
	f.results, f.audits, f.jobs = copy.results, copy.audits, copy.jobs
	return nil
}
func releaseManifestCheckpointFixture(t *testing.T) (*ReleaseManifestCheckpointCommands, *releaseManifestCheckpointFake) {
	t.Helper()
	c, a := auditVerificationFixture(t)
	f := &releaseManifestCheckpointFake{*a}
	f.snapshot.Manifest = map[string]any{"chain_checkpoint": map[string]any{"sequence": 1, "head_hash": f.view.HeadHash}}
	hash, err := application.NormalizedJSONHash(f.snapshot.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot.ManifestHash = hash
	command, err := NewReleaseManifestCheckpointCommands(ReleaseManifestCheckpointConfig{Transactions: f, Authorizer: f, Hasher: auditHashTestAdapter{}, Verifier: merkleVectorVerifier{hash}, Clock: c.config.Clock, IDs: c.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return command, f
}
func TestReleaseManifestCheckpointUsesDistinctProfileAndAtomicReceipt(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	c, f := releaseManifestCheckpointFixture(t)
	r, err := c.VerifyReleaseManifestCheckpoint(t.Context(), actor, "bundle")
	if err != nil || r.Result.String() != "passed" || r.SubjectType != "audit_chain_release_manifest" || r.SubjectID != "bundle" || r.Profile.ID != verificationdomain.VerificationProfileAuditChainReleaseManifest || r.Profile.PayloadDigest != f.snapshot.ManifestHash || r.Profile.TransparencyProof != "not_evaluated" || len(r.Checks) != 11 || r.Checks[8].Name != "checkpoint_manifest_hash" || r.Checks[9].Name != "checkpoint_signature" || r.Checks[10].Name != "checkpoint_coverage" || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 {
		t.Fatal(r, err, f)
	}
	for _, failure := range []string{"read", "result", "audit", "outbox", "commit"} {
		c, f = releaseManifestCheckpointFixture(t)
		f.fail = failure
		r, err := c.VerifyReleaseManifestCheckpoint(t.Context(), actor, "bundle")
		if !errors.Is(err, errVerificationTestFailure) || r.ID != "" || len(f.results)+len(f.audits)+len(f.jobs) != 0 {
			t.Fatal(failure, r, err)
		}
	}
	c, f = releaseManifestCheckpointFixture(t)
	f.fail = "auth"
	if _, err := c.VerifyReleaseManifestCheckpoint(t.Context(), actor, "bundle"); !errors.Is(err, application.ErrForbidden) || f.payloadReads+f.pageReads != 0 {
		t.Fatal("unauthorized read", err)
	}
	c, f = releaseManifestCheckpointFixture(t)
	f.subject.TenantID = "foreign"
	if _, err := c.VerifyReleaseManifestCheckpoint(t.Context(), actor, "bundle"); !errors.Is(err, ErrNotFound) || f.payloadReads != 1 || f.pageReads != 0 {
		t.Fatal("foreign content read", err)
	}
	for _, id := range []string{"", " ", "bad\x00id", string([]byte{255}), strings.Repeat("x", 1025)} {
		c, f = releaseManifestCheckpointFixture(t)
		if _, err := c.VerifyReleaseManifestCheckpoint(t.Context(), actor, id); !errors.Is(err, ErrValidation) || f.payloadReads+f.pageReads != 0 {
			t.Fatal("invalid ID", err)
		}
	}
	c, f = releaseManifestCheckpointFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.VerifyReleaseManifestCheckpoint(ctx, actor, "bundle"); !errors.Is(err, context.Canceled) || f.payloadReads != 0 {
		t.Fatal(err)
	}
}
func TestReleaseManifestCheckpointChecksCanonicalChainAndCoveredHead(t *testing.T) {
	for name, mutate := range map[string]func(*releaseManifestCheckpointFake){
		"canonical metadata": func(f *releaseManifestCheckpointFake) { f.pages[0].Entries[0].Metadata["safe"] = "tampered" },
		"manifest":           func(f *releaseManifestCheckpointFake) { f.snapshot.Manifest["changed"] = true },
		"covered hash": func(f *releaseManifestCheckpointFake) {
			f.snapshot.Manifest["chain_checkpoint"].(map[string]any)["head_hash"] = "other"
		},
		"missing checkpoint": func(f *releaseManifestCheckpointFake) { delete(f.snapshot.Manifest, "chain_checkpoint") },
		"truncated tail": func(f *releaseManifestCheckpointFake) {
			f.snapshot.Manifest["chain_checkpoint"].(map[string]any)["sequence"] = 2
		},
		"signature subject": func(f *releaseManifestCheckpointFake) { f.snapshot.Signatures[0].SubjectID = "other" },
		"signature tenant":  func(f *releaseManifestCheckpointFake) { f.snapshot.Signatures[0].TenantID = "foreign" },
		"key tenant":        func(f *releaseManifestCheckpointFake) { f.snapshot.Keys[0].TenantID = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			c, f := releaseManifestCheckpointFixture(t)
			mutate(f)
			r, err := c.VerifyReleaseManifestCheckpoint(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "bundle")
			if !errors.Is(err, ErrVerificationFailed) || r.Result.String() != "failed" || len(r.Checks) != 11 || len(f.results) != 1 {
				t.Fatal(r, err)
			}
			if (name == "covered hash" || name == "missing checkpoint" || name == "truncated tail") && r.Checks[10].Result != "failed" {
				t.Fatal("coverage failure was not detected", r)
			}
		})
	}
	for _, large := range []bool{false, true} {
		c, f := releaseManifestCheckpointFixture(t)
		if large {
			f.snapshot.Manifest["large"] = strings.Repeat("x", MaxBundleVerificationBytes+1)
		} else {
			f.snapshot.SignatureRefs = make([]string, MaxBundleVerificationSignatures+1)
		}
		r, err := c.VerifyReleaseManifestCheckpoint(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "bundle")
		if !errors.Is(err, ErrConflict) || r.ID != "" || len(f.results) != 0 {
			t.Fatal(r, err)
		}
	}
}

func TestReleaseManifestCheckpointChecksPagesBeyondCoveredPrefix(t *testing.T) {
	c, f := releaseManifestCheckpointFixture(t)
	second := f.pages[0].Entries[0]
	second.ID, second.Sequence, second.PreviousEntryHash = "second", 2, f.view.HeadHash
	if err := RehashAuditChainEntry(&second, auditHashTestAdapter{}); err != nil {
		t.Fatal(err)
	}
	f.view.EntryCount, f.view.HeadSequence, f.view.HeadHash = 2, 2, second.EntryHash
	f.pages = append(f.pages, AuditChainVerificationPage{Entries: []verificationdomain.AuditChainEntry{second}, BytesRead: 1024})
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	r, err := c.VerifyReleaseManifestCheckpoint(t.Context(), actor, "bundle")
	if err != nil || r.Result.String() != "passed" || len(r.Checks) != 18 || f.pageReads != 3 {
		t.Fatal(r, err, f.pageReads)
	}
	f.pages[1].Entries[0].ActorID = "tampered"
	r, err = c.VerifyReleaseManifestCheckpoint(t.Context(), actor, "bundle")
	if !errors.Is(err, ErrVerificationFailed) || r.Checks[17].Result != "passed" || r.Checks[14].Result != "failed" {
		t.Fatal("tampering beyond covered prefix", r, err)
	}
	c, f = releaseManifestCheckpointFixture(t)
	f.snapshot.Manifest = map[string]any{"chain_checkpoint": map[string]any{"sequence": 0, "head_hash": ""}}
	hash, err := application.NormalizedJSONHash(f.snapshot.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot.ManifestHash = hash
	c.config.Verifier = merkleVectorVerifier{hash}
	r, err = c.VerifyReleaseManifestCheckpoint(t.Context(), actor, "bundle")
	if err != nil || r.Checks[10].Result != "passed" {
		t.Fatal("zero-sequence compatibility", r, err)
	}
}
func TestReleaseManifestCheckpointParserPreservesIntegerRepresentations(t *testing.T) {
	for _, value := range []any{int(1), int64(1), float64(1)} {
		sequence, head, ok := ReleaseManifestAuditChainCheckpoint(map[string]any{"chain_checkpoint": map[string]any{"sequence": value, "head_hash": "head"}})
		if !ok || sequence != 1 || head != "head" {
			t.Fatal(value, sequence, head, ok)
		}
	}
	for _, value := range []any{nil, "1", float64(1.5), math.NaN(), math.Inf(1), float64(1 << 63)} {
		if _, _, ok := ReleaseManifestAuditChainCheckpoint(map[string]any{"chain_checkpoint": map[string]any{"sequence": value, "head_hash": "head"}}); ok {
			t.Fatal("malformed sequence accepted", value)
		}
	}
}
