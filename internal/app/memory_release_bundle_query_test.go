package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func memoryReleaseBundlePointFixture(t *testing.T) (*memoryUnitOfWork, packagequery.ReleaseBundleReader) {
	t.Helper()
	tx, _ := memoryReadinessQueryFixture(t)
	reader, ok := tx.Repositories().Packages.(packagequery.ReleaseBundleReader)
	if !ok {
		t.Fatal("memory Package repository lacks the native release-bundle point reader")
	}
	published, revoked := fixedNow(), fixedNow().AddDate(0, 0, 1)
	tx.state.ReleaseBundles["bundle"] = domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "tenant-release", State: "revoked", Manifest: map[string]any{"release": map[string]any{"id": "tenant-release", "revision": json.Number("2")}, "evidence_ids": []any{"tenant-evidence"}}, ManifestHash: "sha256:fixture", SignatureRefs: []string{"sig-a", "sig-b"}, CreatedAt: fixedNow(), PublishedAt: &published, RevokedAt: &revoked}
	return tx, reader
}

func TestMemoryReleaseBundlePointReturnsCompleteDetachedMetadataAndCurrentParent(t *testing.T) {
	tx, reader := memoryReleaseBundlePointFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	state, err := packagedomain.ParseBundleState("revoked")
	if err != nil {
		t.Fatal(err)
	}
	published, revoked := fixedNow(), fixedNow().AddDate(0, 0, 1)
	want := packagequery.ReleaseBundlePoint{ProductID: "tenant-product", Bundle: packagedomain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "tenant-release", State: state, Manifest: map[string]any{"release": map[string]any{"id": "tenant-release", "revision": json.Number("2")}, "evidence_ids": []any{"tenant-evidence"}}, ManifestHash: "sha256:fixture", SignatureRefs: []string{"sig-a", "sig-b"}, CreatedAt: fixedNow(), PublishedAt: &published, RevokedAt: &revoked}}
	value, err := reader.GetReleaseBundlePoint(t.Context(), "tenant", " bundle ")
	if err != nil || !reflect.DeepEqual(value, want) {
		t.Fatal("release-bundle point lost complete recorded metadata or current scope", value, want, err)
	}
	value.Bundle.Manifest["release"].(map[string]any)["revision"] = -1
	value.Bundle.Manifest["evidence_ids"].([]any)[0] = "changed"
	value.Bundle.SignatureRefs[0] = "changed"
	*value.Bundle.PublishedAt, *value.Bundle.RevokedAt = revoked, published
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("point read or caller mutation altered recorded bundle data")
	}
	service, err := packagequery.NewReleaseBundles(reader)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: "tenant", UserID: "reader", Scopes: []string{"bundle:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "tenant-product", Scopes: []string{"bundle:read"}}}}
	if got, err := service.GetReleaseBundle(t.Context(), human, "bundle"); err != nil || !reflect.DeepEqual(got, want.Bundle) {
		t.Fatal("native query lost recorded bundle fields", got, err)
	}
	p := tx.state.Products["tenant-product"]
	p.ID = "current-product"
	tx.state.Products[p.ID] = p
	r := tx.state.Releases["tenant-release"]
	r.ProductID = p.ID
	tx.state.Releases[r.ID] = r
	if value, err := service.GetReleaseBundle(t.Context(), human, "bundle"); !errors.Is(err, application.ErrForbidden) || !reflect.DeepEqual(value, packagedomain.ReleaseBundle{}) {
		t.Fatal("stale product grant remained authoritative", value, err)
	}
	human.ResourceGrants[0].ResourceID = p.ID
	if value, err := service.GetReleaseBundle(t.Context(), human, "bundle"); err != nil || !reflect.DeepEqual(value, want.Bundle) {
		t.Fatal("current product grant did not permit the native bundle read", value, err)
	}
}

func TestMemoryReleaseBundlePointRejectsForeignMissingOrMalformedCurrentRows(t *testing.T) {
	for _, kind := range []string{"foreign-bundle", "foreign-release", "foreign-product", "missing-release", "missing-product", "mismatched-id", "state", "manifest", "signatures", "unserializable"} {
		t.Run(kind, func(t *testing.T) {
			tx, reader := memoryReleaseBundlePointFixture(t)
			b := tx.state.ReleaseBundles["bundle"]
			wantErr := packagequery.ErrReleaseBundleNotFound
			switch kind {
			case "foreign-bundle":
				b.TenantID = "foreign"
			case "foreign-release":
				r := tx.state.Releases[b.ReleaseID]
				r.TenantID = "foreign"
				tx.state.Releases[r.ID] = r
			case "foreign-product":
				p := tx.state.Products["tenant-product"]
				p.TenantID = "foreign"
				tx.state.Products[p.ID] = p
			case "missing-release":
				delete(tx.state.Releases, b.ReleaseID)
			case "missing-product":
				delete(tx.state.Products, "tenant-product")
			case "mismatched-id":
				b.ID = "unrelated"
			case "state":
				b.State, wantErr = "unknown", packagequery.ErrReleaseBundleProjection
			case "manifest":
				b.Manifest, wantErr = nil, packagequery.ErrReleaseBundleProjection
			case "signatures":
				b.SignatureRefs, wantErr = nil, packagequery.ErrReleaseBundleProjection
			case "unserializable":
				b.Manifest["private"] = make(chan int)
				wantErr = packagequery.ErrReleaseBundleProjection
			}
			tx.state.ReleaseBundles["bundle"] = b
			if value, err := reader.GetReleaseBundlePoint(t.Context(), "tenant", "bundle"); !errors.Is(err, wantErr) || !reflect.DeepEqual(value, packagequery.ReleaseBundlePoint{}) {
				t.Fatal("unsafe bundle point returned recorded or partial data", value, err)
			}
		})
	}
}

func TestMemoryReleaseBundlePointPreservesEmptySignaturesAndFailureCleanup(t *testing.T) {
	tx, reader := memoryReleaseBundlePointFixture(t)
	b := tx.state.ReleaseBundles["bundle"]
	b.SignatureRefs = []string{}
	tx.state.ReleaseBundles[b.ID] = b
	if value, err := reader.GetReleaseBundlePoint(t.Context(), "tenant", b.ID); err != nil || value.Bundle.SignatureRefs == nil || len(value.Bundle.SignatureRefs) != 0 {
		t.Fatal("valid empty signature array became null", value, err)
	}
	for _, id := range []string{"", "missing"} {
		if value, err := reader.GetReleaseBundlePoint(t.Context(), "tenant", id); !errors.Is(err, packagequery.ErrReleaseBundleNotFound) || !reflect.DeepEqual(value, packagequery.ReleaseBundlePoint{}) {
			t.Fatal("missing bundle returned point data", value, err)
		}
	}
	var absent context.Context
	if _, err := reader.GetReleaseBundlePoint(absent, "tenant", b.ID); !errors.Is(err, packagequery.ErrValidation) {
		t.Fatal("nil bundle read context accepted", err)
	}
	if _, err := reader.GetReleaseBundlePoint(t.Context(), " ", b.ID); !errors.Is(err, packagequery.ErrValidation) {
		t.Fatal("blank bundle tenant accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := reader.GetReleaseBundlePoint(ctx, "tenant", b.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, packagequery.ReleaseBundlePoint{}) {
		t.Fatal("canceled point returned bundle data", value, err)
	}
	base, cancelDuringRead := context.WithCancel(t.Context())
	defer cancelDuringRead()
	during := &memoryBundleCancelAfterSelection{Context: base, cancel: cancelDuringRead}
	if value, err := reader.GetReleaseBundlePoint(during, "tenant", b.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, packagequery.ReleaseBundlePoint{}) || during.checks != 3 {
		t.Fatal("post-selection cancellation returned partial bundle data", value, err)
	}
	if _, err := reader.GetReleaseBundlePoint(t.Context(), "tenant", b.ID); err != nil {
		t.Fatal("failed read retained transaction lock", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if value, err := reader.GetReleaseBundlePoint(t.Context(), "tenant", b.ID); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, packagequery.ReleaseBundlePoint{}) {
		t.Fatal("closed transaction returned bundle point", value, err)
	}
}

type memoryBundleCancelAfterSelection struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *memoryBundleCancelAfterSelection) Err() error {
	c.checks++
	if c.checks == 3 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestMemoryReleaseBundlePointPreservesExactNumbersAcrossRepositoryCopies(t *testing.T) {
	for _, boundary := range []string{"point", "insert", "transaction"} {
		t.Run(boundary, func(t *testing.T) {
			tx, reader := memoryReleaseBundlePointFixture(t)
			b := tx.state.ReleaseBundles["bundle"]
			b.Manifest = map[string]any{"decimal": json.Number("0.12345678901234567890123456789"), "integer": json.Number("9007199254740993"), "nested": []any{json.Number("18446744073709551615"), map[string]any{"negative": json.Number("-9007199254740993")}}}
			want, err := json.Marshal(b.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			tx.state.ReleaseBundles[b.ID] = b
			switch boundary {
			case "insert":
				delete(tx.state.ReleaseBundles, b.ID)
				if err := tx.Repositories().Packages.InsertReleaseBundle(t.Context(), b); err != nil {
					t.Fatal(err)
				}
			case "transaction":
				if err := tx.Commit(t.Context()); err != nil {
					t.Fatal(err)
				}
				snapshot, err := tx.factory.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := json.Marshal(snapshot.ReleaseBundles[b.ID].Manifest)
				if err != nil || !bytes.Equal(encoded, want) {
					t.Fatal("commit or snapshot rounded signed bundle numbers", string(encoded), err)
				}
				next, err := tx.factory.BeginUnitOfWork(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := next.Rollback(t.Context()); err != nil {
						t.Error(err)
					}
				}()
				reader = next.Repositories().Packages.(packagequery.ReleaseBundleReader)
			}
			value, err := reader.GetReleaseBundlePoint(t.Context(), "tenant", b.ID)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(value.Bundle.Manifest)
			if err != nil || !bytes.Equal(encoded, want) {
				t.Fatal("repository copy rounded signed bundle numbers", string(encoded), err)
			}
		})
	}
}
