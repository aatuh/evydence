package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

var errDenied = errors.New("denied")
var errAudit = errors.New("audit failed")

func TestCreateProductAuthorizesBeforeOneAtomicTransaction(t *testing.T) {
	fixture := newServiceFixture(t)
	product, err := fixture.service.CreateProduct(context.Background(), fixture.actor, CreateProductInput{Name: " Payments ", Slug: " payments "})
	if err != nil {
		t.Fatalf("CreateProduct: %v", err)
	}
	if product.ID != "prod_1" || product.TenantID != fixture.actor.TenantID || product.Name != "Payments" || product.Slug != "payments" || !product.CreatedAt.Equal(fixture.now) {
		t.Fatalf("product = %#v", product)
	}
	if fixture.authorizer.calls != 1 || fixture.authorizer.transactionStartedAtCall {
		t.Fatalf("authorization calls=%d transaction_started_at_call=%t", fixture.authorizer.calls, fixture.authorizer.transactionStartedAtCall)
	}
	if fixture.transactions.calls != 1 || fixture.transactions.commits != 1 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("transactions = %#v", fixture.transactions)
	}
	stored, ok := fixture.transactions.state.products[product.ID]
	if !ok || !reflect.DeepEqual(stored, product) {
		t.Fatalf("committed product = %#v, ok=%t", stored, ok)
	}
	if len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("audit = %#v", fixture.transactions.state.audit)
	}
	event := fixture.transactions.state.audit[0]
	if event.EntryType != "product.created" || event.SubjectType != "product" || event.SubjectID != product.ID || event.ActorID != fixture.actor.KeyID || event.TenantID != fixture.actor.TenantID {
		t.Fatalf("audit event = %#v", event)
	}
}

func TestListProductsPropagatesPerResourceCancellation(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.reader.products["prod_1"] = releasedomain.Product{ID: "prod_1", TenantID: fixture.actor.TenantID, Name: "Product", Slug: "product", CreatedAt: fixture.now}
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources.ProductID != "" {
			return context.Canceled
		}
		return nil
	}

	if _, err := fixture.service.ListProducts(context.Background(), fixture.actor); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListProducts error = %v, want cancellation", err)
	}
}

func TestListProductsFiltersCanonicalResourceDenial(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.reader.products["prod_1"] = releasedomain.Product{ID: "prod_1", TenantID: fixture.actor.TenantID, Name: "Product", Slug: "product", CreatedAt: fixture.now}
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources.ProductID != "" {
			return ErrForbidden
		}
		return nil
	}

	products, err := fixture.service.ListProducts(context.Background(), fixture.actor)
	if err != nil || len(products) != 0 {
		t.Fatalf("ListProducts = (%#v, %v), want filtered result", products, err)
	}
}

func TestCreateProductAttributesHumanSessionAuditToUser(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.actor.KeyID = ""
	fixture.actor.UserID = "usr_1"
	fixture.actor.SessionID = "sess_1"

	if _, err := fixture.service.CreateProduct(context.Background(), fixture.actor, CreateProductInput{Name: "Product", Slug: "product"}); err != nil {
		t.Fatalf("CreateProduct: %v", err)
	}
	if len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("audit = %#v", fixture.transactions.state.audit)
	}
	event := fixture.transactions.state.audit[0]
	if event.ActorType != "human_user" || event.ActorID != fixture.actor.UserID {
		t.Fatalf("audit actor = (%q, %q), want human user", event.ActorType, event.ActorID)
	}
}

func TestCreateProductDeniedBeforeRepositoryOrTransaction(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.authorizer.err = errDenied
	_, err := fixture.service.CreateProduct(context.Background(), fixture.actor, CreateProductInput{Name: "Payments", Slug: "payments"})
	if !errors.Is(err, errDenied) {
		t.Fatalf("CreateProduct error = %v, want denied", err)
	}
	if fixture.transactions.calls != 0 || fixture.reader.calls != 0 {
		t.Fatalf("denied command touched reader=%d transactions=%d", fixture.reader.calls, fixture.transactions.calls)
	}
}

func TestCatalogQueriesRejectHostileReaderResults(t *testing.T) {
	tests := []struct {
		name   string
		invoke func(*serviceFixture) error
	}{
		{
			name: "product from another tenant",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getProduct: func(context.Context, string, string) (releasedomain.Product, error) {
					return releasedomain.Product{ID: "prod_1", TenantID: "ten_other", Slug: "product"}, nil
				}}
				_, err := fixture.service.GetProduct(context.Background(), fixture.actor, "prod_1")
				return err
			},
		},
		{
			name: "product with another id",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getProduct: func(context.Context, string, string) (releasedomain.Product, error) {
					return releasedomain.Product{ID: "prod_other", TenantID: fixture.actor.TenantID, Slug: "product"}, nil
				}}
				_, err := fixture.service.GetProduct(context.Background(), fixture.actor, "prod_1")
				return err
			},
		},
		{
			name: "project from another tenant",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getProject: func(context.Context, string, string) (releasedomain.Project, error) {
					return releasedomain.Project{ID: "proj_1", TenantID: "ten_other", ProductID: "prod_1"}, nil
				}}
				_, err := fixture.service.GetProject(context.Background(), fixture.actor, "proj_1")
				return err
			},
		},
		{
			name: "project with another id",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getProject: func(context.Context, string, string) (releasedomain.Project, error) {
					return releasedomain.Project{ID: "proj_other", TenantID: fixture.actor.TenantID, ProductID: "prod_1"}, nil
				}}
				_, err := fixture.service.GetProject(context.Background(), fixture.actor, "proj_1")
				return err
			},
		},
		{
			name: "project with missing parent",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getProject: func(context.Context, string, string) (releasedomain.Project, error) {
					return releasedomain.Project{ID: "proj_1", TenantID: fixture.actor.TenantID, ProductID: "prod_other"}, nil
				}}
				_, err := fixture.service.GetProject(context.Background(), fixture.actor, "proj_1")
				return err
			},
		},
		{
			name: "release from another tenant",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getRelease: func(context.Context, string, string) (releasedomain.Release, error) {
					return releasedomain.Release{ID: "rel_1", TenantID: "ten_other", ProductID: "prod_1"}, nil
				}}
				_, err := fixture.service.GetRelease(context.Background(), fixture.actor, "rel_1")
				return err
			},
		},
		{
			name: "release with another id",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getRelease: func(context.Context, string, string) (releasedomain.Release, error) {
					return releasedomain.Release{ID: "rel_other", TenantID: fixture.actor.TenantID, ProductID: "prod_1"}, nil
				}}
				_, err := fixture.service.GetRelease(context.Background(), fixture.actor, "rel_1")
				return err
			},
		},
		{
			name: "release with missing parent",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getRelease: func(context.Context, string, string) (releasedomain.Release, error) {
					return releasedomain.Release{ID: "rel_1", TenantID: fixture.actor.TenantID, ProductID: "prod_other"}, nil
				}}
				_, err := fixture.service.GetRelease(context.Background(), fixture.actor, "rel_1")
				return err
			},
		},
		{
			name: "artifact from another tenant",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getArtifact: func(context.Context, string, string) (releasedomain.Artifact, error) {
					return releasedomain.Artifact{ID: "art_1", TenantID: "ten_other", Digest: testSHA256('a')}, nil
				}}
				_, err := fixture.service.GetArtifact(context.Background(), fixture.actor, "art_1")
				return err
			},
		},
		{
			name: "artifact with another id",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getArtifact: func(context.Context, string, string) (releasedomain.Artifact, error) {
					return releasedomain.Artifact{ID: "art_other", TenantID: fixture.actor.TenantID, Digest: testSHA256('a')}, nil
				}}
				_, err := fixture.service.GetArtifact(context.Background(), fixture.actor, "art_1")
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			if err := test.invoke(fixture); !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v, want not found", err)
			}
			if fixture.transactions.calls != 0 {
				t.Fatalf("hostile read started %d transactions", fixture.transactions.calls)
			}
		})
	}
}

func TestCreateProjectAndReleaseRejectHostileProductReads(t *testing.T) {
	for _, test := range []struct {
		name   string
		invoke func(*serviceFixture) error
	}{
		{
			name: "project",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getProduct: func(context.Context, string, string) (releasedomain.Product, error) {
					return releasedomain.Product{ID: "prod_other", TenantID: fixture.actor.TenantID, Slug: "other"}, nil
				}}
				_, err := fixture.service.CreateProject(context.Background(), fixture.actor, CreateProjectInput{ProductID: "prod_1", Name: "Project"})
				return err
			},
		},
		{
			name: "release",
			invoke: func(fixture *serviceFixture) error {
				fixture.service.reader = readerOverride{Reader: fixture.reader, getProduct: func(context.Context, string, string) (releasedomain.Product, error) {
					return releasedomain.Product{ID: "prod_1", TenantID: "ten_other", Slug: "product"}, nil
				}}
				_, err := fixture.service.CreateRelease(context.Background(), fixture.actor, CreateReleaseInput{ProductID: "prod_1", Version: "1.0.0"})
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			if err := test.invoke(fixture); !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v, want not found", err)
			}
			if fixture.transactions.calls != 0 {
				t.Fatalf("hostile read started %d transactions", fixture.transactions.calls)
			}
		})
	}
}

func TestCreateProjectAndReleaseRejectTransactionalProductDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		invoke func(*serviceFixture, releasedomain.Product) error
	}{
		{
			name: "project",
			invoke: func(fixture *serviceFixture, product releasedomain.Product) error {
				_, err := fixture.service.CreateProject(context.Background(), fixture.actor, CreateProjectInput{ProductID: product.ID, Name: "Project"})
				return err
			},
		},
		{
			name: "release",
			invoke: func(fixture *serviceFixture, product releasedomain.Product) error {
				_, err := fixture.service.CreateRelease(context.Background(), fixture.actor, CreateReleaseInput{ProductID: product.ID, Version: "1.0.0"})
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			product := releasedomain.Product{ID: "prod_1", TenantID: fixture.actor.TenantID, Name: "Product", Slug: "product", CreatedAt: fixture.now}
			fixture.reader.products[product.ID] = product
			fixture.transactions.state.products[product.ID] = product
			fixture.transactions.beforeCommand = func(state *fakeState) {
				changed := state.products[product.ID]
				changed.ID = "prod_other"
				state.products[product.ID] = changed
			}

			if err := test.invoke(fixture, product); !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v, want not found", err)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
				t.Fatalf("transactions = %#v", fixture.transactions)
			}
		})
	}
}

func TestReleaseTransitionRejectsHostileReaderAndTransactionalCoordinates(t *testing.T) {
	state, _ := releasedomain.ParseReleaseState(releasedomain.ReleaseStateDraftValue)
	t.Run("reader parent", func(t *testing.T) {
		fixture := newServiceFixture(t)
		fixture.service.reader = readerOverride{Reader: fixture.reader, getRelease: func(context.Context, string, string) (releasedomain.Release, error) {
			return releasedomain.Release{ID: "rel_1", TenantID: fixture.actor.TenantID, ProductID: "prod_other", Version: "1.0.0", Revision: 1, State: state}, nil
		}}
		if _, err := fixture.service.FreezeRelease(context.Background(), fixture.actor, "rel_1", 1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("error = %v, want not found", err)
		}
		if fixture.transactions.calls != 0 {
			t.Fatalf("transactions = %d, want 0", fixture.transactions.calls)
		}
	})

	t.Run("transaction id", func(t *testing.T) {
		fixture := newServiceFixture(t)
		product := releasedomain.Product{ID: "prod_1", TenantID: fixture.actor.TenantID, Slug: "product"}
		release := releasedomain.Release{ID: "rel_1", TenantID: fixture.actor.TenantID, ProductID: product.ID, Version: "1.0.0", Revision: 1, State: state}
		fixture.reader.products[product.ID] = product
		fixture.reader.releases[release.ID] = release
		fixture.transactions.state.releases[release.ID] = release
		fixture.transactions.beforeCommand = func(state *fakeState) {
			changed := state.releases[release.ID]
			changed.ID = "rel_other"
			state.releases[release.ID] = changed
		}
		if _, err := fixture.service.FreezeRelease(context.Background(), fixture.actor, release.ID, 1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("error = %v, want not found", err)
		}
		if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
			t.Fatalf("transactions = %#v", fixture.transactions)
		}
	})

	t.Run("transaction parent", func(t *testing.T) {
		fixture := newServiceFixture(t)
		product := releasedomain.Product{ID: "prod_1", TenantID: fixture.actor.TenantID, Slug: "product"}
		release := releasedomain.Release{ID: "rel_1", TenantID: fixture.actor.TenantID, ProductID: product.ID, Version: "1.0.0", Revision: 1, State: state}
		fixture.reader.products[product.ID] = product
		fixture.reader.releases[release.ID] = release
		fixture.transactions.state.releases[release.ID] = release
		fixture.transactions.beforeCommand = func(state *fakeState) {
			changed := state.releases[release.ID]
			changed.ProductID = "prod_other"
			state.releases[release.ID] = changed
		}
		if _, err := fixture.service.FreezeRelease(context.Background(), fixture.actor, release.ID, 1); !errors.Is(err, ErrConflict) {
			t.Fatalf("error = %v, want conflict", err)
		}
		if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
			t.Fatalf("transactions = %#v", fixture.transactions)
		}
	})
}

func TestRegisterArtifactRejectsHostileDeduplicationResult(t *testing.T) {
	for _, test := range []struct {
		name    string
		result  releasedomain.Artifact
		wantErr error
	}{
		{name: "foreign tenant", result: releasedomain.Artifact{ID: "art_other", TenantID: "ten_other", Digest: testSHA256('a')}, wantErr: ErrNotFound},
		{name: "wrong digest", result: releasedomain.Artifact{ID: "art_other", TenantID: "ten_1", Digest: testSHA256('b')}, wantErr: ErrConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			fixture.transactions.wrap = func(tx Transaction) Transaction {
				return transactionOverride{Transaction: tx, catalog: catalogOverride{
					CatalogRepository: tx.Catalog(),
					artifactByDigest: func(context.Context, string, string) (releasedomain.Artifact, bool, error) {
						return test.result, true, nil
					},
				}}
			}
			_, err := fixture.service.RegisterArtifact(context.Background(), fixture.actor, RegisterArtifactInput{
				Name: "artifact", MediaType: "application/octet-stream", Digest: testSHA256('a'), Size: 1,
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
				t.Fatalf("transactions = %#v", fixture.transactions)
			}
		})
	}
}

func TestRegisterArtifactExistingDigestRequiresExactArtifactAuthorization(t *testing.T) {
	existing := releasedomain.Artifact{
		ID: "art_existing", TenantID: "ten_1", Name: "existing", MediaType: "application/octet-stream",
		Digest: testSHA256('a'), Size: 1, CreatedAt: time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC),
	}

	t.Run("denied", func(t *testing.T) {
		fixture := newServiceFixture(t)
		fixture.transactions.state.artifacts[existing.ID] = existing
		fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
			if request.Resources == (application.ResourceReferences{ArtifactID: existing.ID}) {
				return errDenied
			}
			return nil
		}

		artifact, err := fixture.service.RegisterArtifact(context.Background(), fixture.actor, RegisterArtifactInput{
			Name: "new name", MediaType: "application/octet-stream", Digest: existing.Digest, Size: 1,
		})
		if !errors.Is(err, errDenied) {
			t.Fatalf("RegisterArtifact error = %v, want denied", err)
		}
		if artifact != (releasedomain.Artifact{}) {
			t.Fatalf("RegisterArtifact leaked existing artifact = %#v", artifact)
		}
		if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || len(fixture.transactions.state.audit) != 0 {
			t.Fatalf("transactions=%#v audit=%#v", fixture.transactions, fixture.transactions.state.audit)
		}
	})

	t.Run("allowed", func(t *testing.T) {
		fixture := newServiceFixture(t)
		fixture.transactions.state.artifacts[existing.ID] = existing

		artifact, err := fixture.service.RegisterArtifact(context.Background(), fixture.actor, RegisterArtifactInput{
			Name: "new name", MediaType: "application/octet-stream", Digest: existing.Digest, Size: 1,
		})
		if err != nil || !reflect.DeepEqual(artifact, existing) {
			t.Fatalf("RegisterArtifact = (%#v, %v), want existing %#v", artifact, err, existing)
		}
		if len(fixture.authorizer.requests) != 2 {
			t.Fatalf("authorization requests = %#v", fixture.authorizer.requests)
		}
		request := fixture.authorizer.requests[1]
		if request.Scope != ScopeEvidenceWrite || request.ScopeOnly || request.Resources != (application.ResourceReferences{ArtifactID: existing.ID}) {
			t.Fatalf("existing artifact authorization = %#v", request)
		}
		if fixture.transactions.commits != 1 || fixture.transactions.rollbacks != 0 || len(fixture.transactions.state.audit) != 0 {
			t.Fatalf("transactions=%#v audit=%#v", fixture.transactions, fixture.transactions.state.audit)
		}
	})
}

func TestFreezeReleaseRollsBackCatalogWhenAuditFails(t *testing.T) {
	fixture := newServiceFixture(t)
	state, err := releasedomain.ParseReleaseState(releasedomain.ReleaseStateDraftValue)
	if err != nil {
		t.Fatal(err)
	}
	release := releasedomain.Release{ID: "rel_1", TenantID: fixture.actor.TenantID, ProductID: "prod_1", Version: "1.0.0", Revision: 1, State: state, CreatedAt: fixture.now}
	fixture.reader.products[release.ProductID] = releasedomain.Product{ID: release.ProductID, TenantID: fixture.actor.TenantID, Slug: "product"}
	fixture.reader.releases[release.ID] = release
	fixture.transactions.state.releases[release.ID] = release
	fixture.transactions.auditErr = errAudit

	_, err = fixture.service.FreezeRelease(context.Background(), fixture.actor, release.ID, release.Revision)
	if !errors.Is(err, errAudit) {
		t.Fatalf("FreezeRelease error = %v, want audit failure", err)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("transactions = %#v", fixture.transactions)
	}
	stored := fixture.transactions.state.releases[release.ID]
	if stored.State.String() != releasedomain.ReleaseStateDraftValue || stored.Revision != 1 || stored.FrozenAt != nil {
		t.Fatalf("release changed after rollback: %#v", stored)
	}
}

func TestFreezeReleaseUsesValidatedLifecycleAndReportsCurrentRevision(t *testing.T) {
	fixture := newServiceFixture(t)
	state, _ := releasedomain.ParseReleaseState(releasedomain.ReleaseStateDraftValue)
	release := releasedomain.Release{ID: "rel_1", TenantID: fixture.actor.TenantID, ProductID: "prod_1", Version: "1.0.0", Revision: 2, State: state, CreatedAt: fixture.now}
	fixture.reader.products[release.ProductID] = releasedomain.Product{ID: release.ProductID, TenantID: fixture.actor.TenantID, Slug: "product"}
	fixture.reader.releases[release.ID] = release
	fixture.transactions.state.releases[release.ID] = release

	if _, err := fixture.service.FreezeRelease(context.Background(), fixture.actor, release.ID, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("FreezeRelease stale revision error = %v", err)
	} else if current, ok := CurrentRevision(err); !ok || current != 2 {
		t.Fatalf("CurrentRevision = %d, %t", current, ok)
	}
	frozen, err := fixture.service.FreezeRelease(context.Background(), fixture.actor, release.ID, 2)
	if err != nil {
		t.Fatalf("FreezeRelease: %v", err)
	}
	if frozen.State.String() != releasedomain.ReleaseStateFrozenValue || frozen.Revision != 3 || frozen.FrozenAt == nil || !frozen.FrozenAt.Equal(fixture.now) {
		t.Fatalf("frozen release = %#v", frozen)
	}
}

func TestFreezeReleaseUsesOneTimestampForStateAndAudit(t *testing.T) {
	fixture := newServiceFixture(t)
	state, _ := releasedomain.ParseReleaseState(releasedomain.ReleaseStateDraftValue)
	release := releasedomain.Release{ID: "rel_1", TenantID: fixture.actor.TenantID, ProductID: "prod_1", Version: "1.0.0", Revision: 1, State: state, CreatedAt: fixture.now}
	fixture.reader.products[release.ProductID] = releasedomain.Product{ID: release.ProductID, TenantID: fixture.actor.TenantID, Slug: "product"}
	fixture.reader.releases[release.ID] = release
	fixture.transactions.state.releases[release.ID] = release
	clockCalls := 0
	fixture.service.clock = application.ClockFunc(func() time.Time {
		at := fixture.now.Add(time.Duration(clockCalls) * time.Minute)
		clockCalls++
		return at
	})

	frozen, err := fixture.service.FreezeRelease(context.Background(), fixture.actor, release.ID, release.Revision)
	if err != nil {
		t.Fatalf("FreezeRelease: %v", err)
	}
	if clockCalls != 1 {
		t.Fatalf("clock calls = %d, want 1", clockCalls)
	}
	if frozen.FrozenAt == nil || len(fixture.transactions.state.audit) != 1 || !frozen.FrozenAt.Equal(fixture.transactions.state.audit[0].OccurredAt) {
		t.Fatalf("frozen=%#v audit=%#v", frozen, fixture.transactions.state.audit)
	}
}

type serviceFixture struct {
	service           *Service
	actor             identitydomain.Actor
	now               time.Time
	reader            *fakeReader
	authorizer        *fakeAuthorizer
	transactions      *fakeTransactions
	references        *fakeCandidateReferenceValidator
	canonicalizer     *fakeReleaseCandidateCanonicalizer
	attestationParser *fakeBuildAttestationParser
	payloadStager     *fakeBuildAttestationPayloadStager
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	reader := &fakeReader{
		products: map[string]releasedomain.Product{}, projects: map[string]releasedomain.Project{},
		releases: map[string]releasedomain.Release{}, artifacts: map[string]releasedomain.Artifact{},
		builds: map[string]releasedomain.BuildRun{}, candidates: map[string]releasedomain.ReleaseCandidate{},
	}
	transactions := &fakeTransactions{state: fakeState{
		products: map[string]releasedomain.Product{}, projects: map[string]releasedomain.Project{},
		releases: map[string]releasedomain.Release{}, artifacts: map[string]releasedomain.Artifact{},
		builds: map[string]releasedomain.BuildRun{}, candidates: map[string]releasedomain.ReleaseCandidate{},
		images: map[string]releasedomain.ContainerImage{}, attestations: map[string]releasedomain.BuildAttestation{},
	}}
	authorizer := &fakeAuthorizer{transactions: transactions}
	transactions.authorizer = authorizer
	references := &fakeCandidateReferenceValidator{}
	canonicalizer := &fakeReleaseCandidateCanonicalizer{hash: "sha256:" + strings.Repeat("c", 64)}
	attestationParser := &fakeBuildAttestationParser{authorizer: authorizer}
	payloadStager := &fakeBuildAttestationPayloadStager{authorizer: authorizer}
	service, err := NewService(Config{
		Reader:              reader,
		Transactions:        transactions,
		Authorizer:          authorizer,
		CandidateReferences: references,
		Canonicalizer:       canonicalizer,
		AttestationParser:   attestationParser,
		PayloadStager:       payloadStager,
		Clock:               application.ClockFunc(func() time.Time { return now }),
		IDs: application.IDGeneratorFunc(func(prefix string) string {
			return prefix + "_1"
		}),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return &serviceFixture{
		service: service, actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"*"}},
		now: now, reader: reader, authorizer: authorizer, transactions: transactions,
		references: references, canonicalizer: canonicalizer, attestationParser: attestationParser, payloadStager: payloadStager,
	}
}

type fakeAuthorizer struct {
	transactions             *fakeTransactions
	calls                    int
	err                      error
	transactionStartedAtCall bool
	requests                 []application.AuthorizationRequest
	authorize                func(application.AuthorizationRequest) error
}

func (f *fakeAuthorizer) Authorize(_ context.Context, _ identitydomain.Actor, request application.AuthorizationRequest) error {
	f.calls++
	f.transactionStartedAtCall = f.transactionStartedAtCall || f.transactions.calls > 0
	f.requests = append(f.requests, request)
	if f.authorize != nil {
		return f.authorize(request)
	}
	return f.err
}

type fakeReader struct {
	calls      int
	products   map[string]releasedomain.Product
	projects   map[string]releasedomain.Project
	releases   map[string]releasedomain.Release
	artifacts  map[string]releasedomain.Artifact
	builds     map[string]releasedomain.BuildRun
	candidates map[string]releasedomain.ReleaseCandidate
}

type readerOverride struct {
	Reader
	getProduct  func(context.Context, string, string) (releasedomain.Product, error)
	getProject  func(context.Context, string, string) (releasedomain.Project, error)
	getRelease  func(context.Context, string, string) (releasedomain.Release, error)
	getArtifact func(context.Context, string, string) (releasedomain.Artifact, error)
}

func (r readerOverride) GetProduct(ctx context.Context, tenantID, id string) (releasedomain.Product, error) {
	if r.getProduct != nil {
		return r.getProduct(ctx, tenantID, id)
	}
	return r.Reader.GetProduct(ctx, tenantID, id)
}

func (r readerOverride) GetProject(ctx context.Context, tenantID, id string) (releasedomain.Project, error) {
	if r.getProject != nil {
		return r.getProject(ctx, tenantID, id)
	}
	return r.Reader.GetProject(ctx, tenantID, id)
}

func (r readerOverride) GetRelease(ctx context.Context, tenantID, id string) (releasedomain.Release, error) {
	if r.getRelease != nil {
		return r.getRelease(ctx, tenantID, id)
	}
	return r.Reader.GetRelease(ctx, tenantID, id)
}

func (r readerOverride) GetArtifact(ctx context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	if r.getArtifact != nil {
		return r.getArtifact(ctx, tenantID, id)
	}
	return r.Reader.GetArtifact(ctx, tenantID, id)
}

func (f *fakeReader) ListProducts(context.Context, string) ([]releasedomain.Product, error) {
	f.calls++
	out := make([]releasedomain.Product, 0, len(f.products))
	for _, value := range f.products {
		out = append(out, value)
	}
	return out, nil
}
func (f *fakeReader) GetProduct(_ context.Context, tenantID, id string) (releasedomain.Product, error) {
	f.calls++
	value, ok := f.products[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.Product{}, ErrNotFound
	}
	return value, nil
}
func (f *fakeReader) GetProject(_ context.Context, tenantID, id string) (releasedomain.Project, error) {
	f.calls++
	value, ok := f.projects[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.Project{}, ErrNotFound
	}
	return value, nil
}
func (f *fakeReader) GetRelease(_ context.Context, tenantID, id string) (releasedomain.Release, error) {
	f.calls++
	value, ok := f.releases[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.Release{}, ErrNotFound
	}
	return value, nil
}
func (f *fakeReader) GetArtifact(_ context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	f.calls++
	value, ok := f.artifacts[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.Artifact{}, ErrNotFound
	}
	return value, nil
}

func (f *fakeReader) GetBuildRun(_ context.Context, tenantID, id string) (releasedomain.BuildRun, error) {
	f.calls++
	value, ok := f.builds[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.BuildRun{}, ErrNotFound
	}
	return value, nil
}

func (f *fakeReader) GetReleaseCandidate(_ context.Context, tenantID, id string) (releasedomain.ReleaseCandidate, error) {
	f.calls++
	value, ok := f.candidates[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.ReleaseCandidate{}, ErrNotFound
	}
	return value, nil
}

func (f *fakeReader) ListReleaseCandidates(_ context.Context, tenantID, releaseID string) ([]releasedomain.ReleaseCandidate, error) {
	f.calls++
	result := make([]releasedomain.ReleaseCandidate, 0, len(f.candidates))
	for _, value := range f.candidates {
		if value.TenantID == tenantID && (releaseID == "" || value.ReleaseID == releaseID) {
			result = append(result, value)
		}
	}
	return result, nil
}

type fakeCandidateReferenceValidator struct {
	calls      int
	err        error
	tenantID   string
	releaseID  string
	references ReleaseCandidateReferences
}

func (f *fakeCandidateReferenceValidator) ValidateReleaseCandidateReferences(_ context.Context, tenantID, releaseID string, references ReleaseCandidateReferences) error {
	f.calls++
	f.tenantID = tenantID
	f.releaseID = releaseID
	f.references = references
	return f.err
}

type fakeReleaseCandidateCanonicalizer struct {
	calls     int
	hash      string
	err       error
	candidate releasedomain.ReleaseCandidate
}

func (f *fakeReleaseCandidateCanonicalizer) HashReleaseCandidate(_ context.Context, candidate releasedomain.ReleaseCandidate) (string, error) {
	f.calls++
	f.candidate = candidate
	return f.hash, f.err
}

type fakeState struct {
	products     map[string]releasedomain.Product
	projects     map[string]releasedomain.Project
	releases     map[string]releasedomain.Release
	artifacts    map[string]releasedomain.Artifact
	builds       map[string]releasedomain.BuildRun
	candidates   map[string]releasedomain.ReleaseCandidate
	images       map[string]releasedomain.ContainerImage
	attestations map[string]releasedomain.BuildAttestation
	evidence     []fakeBuildAttestationEvidenceCommand
	outbox       []application.OutboxEvent
	audit        []application.AuditEvent
}

func (s fakeState) clone() fakeState {
	clone := fakeState{
		products: map[string]releasedomain.Product{}, projects: map[string]releasedomain.Project{},
		releases: map[string]releasedomain.Release{}, artifacts: map[string]releasedomain.Artifact{},
		builds: map[string]releasedomain.BuildRun{}, candidates: map[string]releasedomain.ReleaseCandidate{},
		images: map[string]releasedomain.ContainerImage{}, attestations: map[string]releasedomain.BuildAttestation{},
		evidence: append([]fakeBuildAttestationEvidenceCommand(nil), s.evidence...),
		outbox:   append([]application.OutboxEvent(nil), s.outbox...), audit: append([]application.AuditEvent(nil), s.audit...),
	}
	for key, value := range s.products {
		clone.products[key] = value
	}
	for key, value := range s.projects {
		clone.projects[key] = value
	}
	for key, value := range s.releases {
		clone.releases[key] = value
	}
	for key, value := range s.artifacts {
		clone.artifacts[key] = value
	}
	for key, value := range s.builds {
		clone.builds[key] = value
	}
	for key, value := range s.candidates {
		clone.candidates[key] = value
	}
	for key, value := range s.images {
		clone.images[key] = value
	}
	for key, value := range s.attestations {
		clone.attestations[key] = value
	}
	return clone
}

type fakeTransactions struct {
	state               fakeState
	calls               int
	commits             int
	rollbacks           int
	auditErr            error
	beforeCommand       func(*fakeState)
	evidenceErr         error
	outboxErr           error
	buildAttestationErr error
	wrap                func(Transaction) Transaction
	authorizer          application.Authorizer
}

func (f *fakeTransactions) Execute(ctx context.Context, command TransactionCommand) error {
	f.calls++
	pending := f.state.clone()
	if f.beforeCommand != nil {
		f.beforeCommand(&pending)
	}
	tx := Transaction(&fakeTransaction{state: &pending, authorizer: f.authorizer, auditErr: f.auditErr, evidenceErr: f.evidenceErr, outboxErr: f.outboxErr, buildAttestationErr: f.buildAttestationErr})
	if f.wrap != nil {
		tx = f.wrap(tx)
	}
	if err := command(ctx, tx); err != nil {
		f.rollbacks++
		return err
	}
	f.state = pending
	f.commits++
	return nil
}

type transactionOverride struct {
	Transaction
	catalog CatalogRepository
}

func (t transactionOverride) Catalog() CatalogRepository { return t.catalog }

type catalogOverride struct {
	CatalogRepository
	artifactByDigest func(context.Context, string, string) (releasedomain.Artifact, bool, error)
}

func (c catalogOverride) ArtifactByDigest(ctx context.Context, tenantID, digest string) (releasedomain.Artifact, bool, error) {
	if c.artifactByDigest != nil {
		return c.artifactByDigest(ctx, tenantID, digest)
	}
	return c.CatalogRepository.ArtifactByDigest(ctx, tenantID, digest)
}

type fakeTransaction struct {
	state               *fakeState
	authorizer          application.Authorizer
	auditErr            error
	evidenceErr         error
	outboxErr           error
	buildAttestationErr error
}

func (f *fakeTransaction) Catalog() CatalogRepository { return fakeCatalog{state: f.state} }
func (f *fakeTransaction) Builds() BuildRepository {
	return fakeBuildRepository{state: f.state, attestationErr: f.buildAttestationErr}
}
func (f *fakeTransaction) BuildAttestationEvidence() BuildAttestationEvidenceWriter {
	return fakeBuildAttestationEvidenceWriter{state: f.state, err: f.evidenceErr}
}
func (f *fakeTransaction) SupplyChain() SupplyChainRepository {
	return fakeSupplyChainRepository{state: f.state}
}
func (f *fakeTransaction) Authorization() application.Authorizer { return f.authorizer }
func (f *fakeTransaction) Audit() application.AuditAppender {
	return fakeAudit{state: f.state, err: f.auditErr}
}
func (f *fakeTransaction) Outbox() application.OutboxEnqueuer {
	return fakeOutbox{state: f.state, err: f.outboxErr}
}

type fakeCatalog struct{ state *fakeState }

func (f fakeCatalog) ProductBySlug(_ context.Context, tenantID, slug string) (releasedomain.Product, bool, error) {
	for _, value := range f.state.products {
		if value.TenantID == tenantID && value.Slug == slug {
			return value, true, nil
		}
	}
	return releasedomain.Product{}, false, nil
}
func (f fakeCatalog) GetProduct(_ context.Context, tenantID, id string) (releasedomain.Product, error) {
	value, ok := f.state.products[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.Product{}, ErrNotFound
	}
	return value, nil
}
func (f fakeCatalog) InsertProduct(_ context.Context, value releasedomain.Product) error {
	f.state.products[value.ID] = value
	return nil
}
func (f fakeCatalog) GetProject(_ context.Context, tenantID, id string) (releasedomain.Project, error) {
	value, ok := f.state.projects[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.Project{}, ErrNotFound
	}
	return value, nil
}
func (f fakeCatalog) GetArtifact(_ context.Context, tenantID, id string) (releasedomain.Artifact, error) {
	value, ok := f.state.artifacts[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.Artifact{}, ErrNotFound
	}
	return value, nil
}
func (f fakeCatalog) InsertProject(_ context.Context, value releasedomain.Project) error {
	f.state.projects[value.ID] = value
	return nil
}
func (f fakeCatalog) ReleaseByVersion(_ context.Context, tenantID, productID, version string) (releasedomain.Release, bool, error) {
	for _, value := range f.state.releases {
		if value.TenantID == tenantID && value.ProductID == productID && value.Version == version {
			return value, true, nil
		}
	}
	return releasedomain.Release{}, false, nil
}
func (f fakeCatalog) GetRelease(_ context.Context, tenantID, id string) (releasedomain.Release, error) {
	value, ok := f.state.releases[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.Release{}, ErrNotFound
	}
	return value, nil
}
func (f fakeCatalog) InsertRelease(_ context.Context, value releasedomain.Release) error {
	f.state.releases[value.ID] = value
	return nil
}
func (f fakeCatalog) UpdateRelease(_ context.Context, value releasedomain.Release, _ int64) error {
	f.state.releases[value.ID] = value
	return nil
}
func (f fakeCatalog) ArtifactByDigest(_ context.Context, tenantID, digest string) (releasedomain.Artifact, bool, error) {
	for _, value := range f.state.artifacts {
		if value.TenantID == tenantID && value.Digest == digest {
			return value, true, nil
		}
	}
	return releasedomain.Artifact{}, false, nil
}
func (f fakeCatalog) InsertArtifact(_ context.Context, value releasedomain.Artifact) error {
	f.state.artifacts[value.ID] = value
	return nil
}

func (f fakeCatalog) GetReleaseCandidate(_ context.Context, tenantID, id string) (releasedomain.ReleaseCandidate, error) {
	value, ok := f.state.candidates[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.ReleaseCandidate{}, ErrNotFound
	}
	return value, nil
}

func (f fakeCatalog) InsertReleaseCandidate(_ context.Context, value releasedomain.ReleaseCandidate) error {
	if _, exists := f.state.candidates[value.ID]; exists {
		return ErrConflict
	}
	f.state.candidates[value.ID] = value
	return nil
}

func (f fakeCatalog) UpdateReleaseCandidateState(_ context.Context, value releasedomain.ReleaseCandidate, expectedRevision int64, expectedState string) error {
	current, ok := f.state.candidates[value.ID]
	if !ok || current.TenantID != value.TenantID || current.ReleaseID != value.ReleaseID {
		return ErrNotFound
	}
	if current.Revision != expectedRevision {
		return NewVersionConflict(current.Revision)
	}
	if current.State.String() != expectedState {
		return ErrConflict
	}
	f.state.candidates[value.ID] = value
	return nil
}

type fakeBuildRepository struct {
	state          *fakeState
	attestationErr error
}

func (f fakeBuildRepository) GetBuildRun(_ context.Context, tenantID, id string) (releasedomain.BuildRun, error) {
	value, ok := f.state.builds[id]
	if !ok || value.TenantID != tenantID {
		return releasedomain.BuildRun{}, ErrNotFound
	}
	return value, nil
}

func (f fakeBuildRepository) InsertBuildRun(_ context.Context, value releasedomain.BuildRun) error {
	if _, exists := f.state.builds[value.ID]; exists {
		return ErrConflict
	}
	f.state.builds[value.ID] = value
	return nil
}

func (f fakeBuildRepository) InsertBuildAttestation(_ context.Context, value releasedomain.BuildAttestation) error {
	if f.attestationErr != nil {
		return f.attestationErr
	}
	if _, exists := f.state.attestations[value.ID]; exists {
		return ErrConflict
	}
	f.state.attestations[value.ID] = value
	return nil
}

type fakeBuildAttestationEvidenceCommand struct {
	actor identitydomain.Actor
	input BuildAttestationEvidenceInput
}

type fakeBuildAttestationEvidenceWriter struct {
	state *fakeState
	err   error
}

func (f fakeBuildAttestationEvidenceWriter) WriteBuildAttestationEvidence(_ context.Context, actor identitydomain.Actor, input BuildAttestationEvidenceInput) (BuildAttestationEvidenceReceipt, error) {
	if f.err != nil {
		return BuildAttestationEvidenceReceipt{}, f.err
	}
	f.state.evidence = append(f.state.evidence, fakeBuildAttestationEvidenceCommand{actor: actor, input: input})
	return BuildAttestationEvidenceReceipt{EvidenceID: "ev_1"}, nil
}

type fakeOutbox struct {
	state *fakeState
	err   error
}

func (f fakeOutbox) EnqueueOutbox(_ context.Context, event application.OutboxEvent) error {
	if f.err != nil {
		return f.err
	}
	f.state.outbox = append(f.state.outbox, event)
	return nil
}

type fakeSupplyChainRepository struct{ state *fakeState }

func (f fakeSupplyChainRepository) ContainerImageByRepositoryDigest(_ context.Context, tenantID, repository, digest string) (releasedomain.ContainerImage, bool, error) {
	for _, value := range f.state.images {
		if value.TenantID == tenantID && value.Repository == repository && value.Digest == digest {
			return value, true, nil
		}
	}
	return releasedomain.ContainerImage{}, false, nil
}

func (f fakeSupplyChainRepository) InsertContainerImage(_ context.Context, value releasedomain.ContainerImage) error {
	if _, exists := f.state.images[value.ID]; exists {
		return ErrConflict
	}
	for _, existing := range f.state.images {
		if existing.TenantID == value.TenantID && existing.Repository == value.Repository && existing.Digest == value.Digest {
			return ErrConflict
		}
	}
	f.state.images[value.ID] = value
	return nil
}

type fakeAudit struct {
	state *fakeState
	err   error
}

func (f fakeAudit) AppendAudit(_ context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	if f.err != nil {
		return application.AuditReceipt{}, f.err
	}
	f.state.audit = append(f.state.audit, event)
	return application.AuditReceipt{ID: event.ID}, nil
}
