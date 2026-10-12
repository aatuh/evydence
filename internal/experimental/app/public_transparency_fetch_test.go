package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type publicFetchFixture struct {
	*publicProofFixture
	endpoint    string
	calls       int
	result      PublicTransparencyFetchedProof
	fetchErr    error
	duringFetch func()
	request     PublicTransparencyProofRequest
}

func (f *publicFetchFixture) ExecutePublicTransparencyFetch(ctx context.Context, _ string, fn func(context.Context, PublicTransparencyFetchTransaction) error) error {
	before, n := ClonePublicTransparencyEntry(f.entry), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errTransparencyMetadataFixture
	}
	if err != nil {
		f.entry, f.audits = before, f.audits[:n]
	}
	return err
}
func (f *publicFetchFixture) ReadPublicTransparencyFetch(ctx context.Context, tenant, id string) (PublicTransparencyFetchSource, error) {
	v, err := f.ReadPublicTransparencyVerification(ctx, tenant, id)
	return PublicTransparencyFetchSource{Entry: v, Endpoint: f.endpoint}, err
}
func (f *publicFetchFixture) FetchTransparencyProof(ctx context.Context, r PublicTransparencyProofRequest) (PublicTransparencyFetchedProof, error) {
	f.calls++
	f.request = r
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 31*time.Second {
		return PublicTransparencyFetchedProof{}, errors.New("unbounded fetch context")
	}
	if f.duringFetch != nil {
		f.duringFetch()
	}
	return f.result, f.fetchErr
}
func publicFetchCommandFixture(t *testing.T) (*PublicTransparencyFetchCommands, *publicFetchFixture, identitydomain.Actor) {
	t.Helper()
	verify, proof, a := publicProofCommandFixture(t)
	f := &publicFetchFixture{publicProofFixture: proof, endpoint: "https://log.example.test", result: PublicTransparencyFetchedProof{Proof: PublicTransparencyProofInput{RootHash: proof.entry.EntryHash, TreeSize: 1}}}
	c, err := NewPublicTransparencyFetchCommands(PublicTransparencyFetchConfig{Transactions: f, Fetcher: f, Clock: verify.config.Clock, IDs: verify.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, a
}
func TestPublicTransparencyFetchFocusedProofHashAndFailureAtomicity(t *testing.T) {
	c, f, a := publicFetchCommandFixture(t)
	if err := c.AuthorizeFetchPublicTransparencyLogEntryProof(t.Context(), a, " entry "); err != nil || f.calls != 0 || len(f.audits) != 0 {
		t.Fatal("guard fetched/wrote", err)
	}
	out, err := c.FetchAndVerifyPublicTransparencyLogEntry(t.Context(), a, " entry ")
	want, _ := application.NormalizedJSONHash(map[string]any{"entry_id": "entry", "leaf_hash": f.entry.EntryHash, "root_hash": f.entry.EntryHash, "leaf_index": 0, "tree_size": 1, "inclusion_proof": nil, "source": "fetched"})
	if err != nil || out.State != "inclusion_verified" || out.InclusionProofHash != want || len(out.VerificationChecks) != 3 || len(out.VerificationLimitations) != 3 || f.calls != 1 || len(f.audits) != 1 || f.audits[0].PayloadHash != want || f.request.Endpoint != f.endpoint || f.request.EntryHash != f.entry.EntryHash || f.request.ExternalID != "external" {
		t.Fatal("fetched verification contract changed", out, err, f.request)
	}
	for _, mode := range []string{"human-product", "foreign", "endpoint", "read", "fetch", "external", "malformed", "proof-count", "changed-entry", "changed-endpoint", "update", "audit", "commit", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			c, f, a := publicFetchCommandFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := ErrValidation
			switch mode {
			case "human-product":
				a.KeyID, a.UserID = "", "user"
				a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: a.Scopes}}
				want = application.ErrForbidden
			case "foreign":
				f.entry.TenantID = "other"
				want = ErrNotFound
			case "endpoint":
				f.endpoint = "https://user:private@log.example.test"
			case "fetch":
				f.fetchErr = errors.New("private provider token")
				want = ErrVerificationFailed
			case "external":
				f.result.ExternalID = "foreign"
				want = ErrVerificationFailed
			case "malformed":
				f.result.Proof.RootHash = "sha256:bad"
				want = ErrVerificationFailed
			case "proof-count":
				f.result.Proof.InclusionProof = make([]string, 65)
				want = ErrVerificationFailed
			case "changed-entry":
				f.duringFetch = func() { f.entry.ExternalID = "changed" }
				want = ErrConflict
			case "changed-endpoint":
				f.duringFetch = func() { f.endpoint = "https://different.example.test" }
				want = ErrConflict
			case "cancel":
				f.duringFetch = cancel
				want = context.Canceled
			default:
				f.phase = mode
				want = errTransparencyMetadataFixture
			}
			before := f.entry
			out, err := c.FetchAndVerifyPublicTransparencyLogEntry(ctx, a, "entry")
			if !errors.Is(err, want) || !reflect.DeepEqual(out, d.PublicTransparencyLogEntry{}) || !reflect.DeepEqual(f.entry, before) || len(f.audits) != 0 {
				t.Fatal("failed fetch published", mode, out, err)
			}
			if (mode == "human-product" || mode == "foreign" || mode == "endpoint" || mode == "read") && f.calls != 0 {
				t.Fatal("invalid source reached provider", mode)
			}
		})
	}
}
func TestPublicTransparencyFetchSourceAndResultBounds(t *testing.T) {
	c, f, a := publicFetchCommandFixture(t)
	c.config.Fetcher = nil
	if out, err := c.FetchAndVerifyPublicTransparencyLogEntry(t.Context(), a, "entry"); !errors.Is(err, ErrValidation) || out.ID != "" || f.reads != 0 || f.calls != 0 {
		t.Fatal("disabled fetch reached data/provider", err)
	}
	for _, bad := range []string{"https://", "https://log.example.test/#private", strings.Repeat(" ", 4097) + "https://log.example.test", "https://log.example.test/\x00"} {
		c, f, a := publicFetchCommandFixture(t)
		f.endpoint = bad
		if out, err := c.FetchAndVerifyPublicTransparencyLogEntry(t.Context(), a, "entry"); !errors.Is(err, ErrValidation) || out.ID != "" || f.calls != 0 {
			t.Fatal("unsafe source endpoint fetched", bad, err)
		}
	}
	if _, err := NewPublicTransparencyFetchCommands(PublicTransparencyFetchConfig{}); err == nil {
		t.Fatal("missing transaction/clock/ID ports accepted")
	}
}

func TestPublicTransparencyFetchFreezesPreviousAssessmentAcrossProviderCall(t *testing.T) {
	c, f, a := publicFetchCommandFixture(t)
	if _, err := c.FetchAndVerifyPublicTransparencyLogEntry(t.Context(), a, "entry"); err != nil {
		t.Fatal(err)
	}
	before, n := ClonePublicTransparencyEntry(f.entry), len(f.audits)
	f.duringFetch = func() { *f.entry.InclusionVerifiedAt = f.entry.InclusionVerifiedAt.Add(time.Second) }
	out, err := c.FetchAndVerifyPublicTransparencyLogEntry(t.Context(), a, "entry")
	if !errors.Is(err, ErrConflict) || out.ID != "" || !reflect.DeepEqual(f.entry, before) || len(f.audits) != n {
		t.Fatal("aliased previous assessment changed fetched authority", out, err)
	}
}
