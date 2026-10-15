package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestPostgresCustomerCreationConcurrentReplayGeneratesOnce(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	body := seedCustomerCreationHTTP(t, pool)
	var request struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatal(err)
	}
	input := packageapp.CreateCustomerPackageInput{ProductID: "product", ReleaseID: "release", RedactionProfileID: "profile", Title: "Review", ExpiresAt: request.ExpiresAt}
	reader, err := postgres.NewCustomerPackageCreationSnapshotReader(store, verificationCanonicalHasher{}, localed25519.PayloadVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var ids atomic.Int32
	commands, err := packageapp.NewCustomerPackageCommands(packageapp.CustomerPackageCommandConfig{
		Reader: reader, Transactions: customerPackageCreationTransactions{store},
		Authorizer: packagequery.NewCustomerPackageCreationAuthorizer(), Hasher: packageCanonicalizer{},
		Clock: application.ClockFunc(func() time.Time { return now }),
		IDs:   application.IDGeneratorFunc(func(prefix string) string { return fmt.Sprintf("%s_stress_%d", prefix, ids.Add(1)) }),
	})
	if err != nil {
		t.Fatal(err)
	}
	executor, err := BuildDurableCommandExecutor(store)
	if err != nil {
		t.Fatal(err)
	}
	canary := newAggregateLoadCanary(t, t.Context(), store)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	type result struct {
		body    string
		err     error
		foreign bool
	}
	const callers = 12
	start := make(chan struct{})
	ready := make(chan struct{}, callers)
	results := make(chan result, callers)
	var effects atomic.Int32
	for i := range callers {
		go func() {
			actor := customerCreationActor()
			foreign := i >= 8
			if foreign {
				actor.TenantID = "other"
			}
			ready <- struct{}{}
			<-start
			_, value, err := executor.WithBody(ctx, actor, "POST", "/v1/customer-packages", "stress", []byte(body), func(ctx context.Context) error {
				return commands.AuthorizeCreateCustomerSecurityPackage(ctx, actor, input)
			}, func(ctx context.Context) (int, any, error) {
				effects.Add(1)
				value, err := commands.CreateCustomerSecurityPackage(ctx, actor, input)
				return 201, packageAccessToLegacy(value), err
			})
			encoded, encodeErr := json.Marshal(value)
			if err == nil {
				err = encodeErr
			}
			results <- result{string(encoded), err, foreign}
		}()
	}
	for range callers {
		<-ready
	}
	close(start)
	var first string
	for range callers {
		select {
		case result := <-results:
			if result.foreign {
				if result.err == nil || result.body != "null" {
					t.Fatal("foreign tenant reached package generation or replay")
				}
				continue
			}
			if result.err != nil || strings.Contains(result.body, "private-") {
				t.Fatal("concurrent package generation failed or leaked private fields", result.err)
			}
			if first == "" {
				first = result.body
			}
			assertRetentionHTTPReplay(t, first, result.body)
		case <-ctx.Done():
			t.Fatal("package command leaked a transaction", ctx.Err())
		}
	}
	if effects.Load() != 1 || customerCreationHTTPCounts(t, pool) != [4]int{1, 1, 1, 0} || !canary.Intact(t.Context()) {
		t.Fatal("concurrent package/replay/foreign commands changed extra state", effects.Load())
	}
}

func TestPostgresWorkerReplicasClaimEachJobOnce(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Tenant'),('other','Other')`); err != nil {
		t.Fatal(err)
	}
	const jobs, replicas = 24, 4
	for i := range jobs {
		tenant := []string{"tenant", "other"}[i%2]
		job := app.OutboxJob{ID: fmt.Sprintf("job_%02d", i), TenantID: tenant, Kind: "parse_sbom", SubjectType: "sbom", SubjectID: fmt.Sprintf("sbom_%02d", i), CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Payload: map[string]any{"owner": tenant}}
		if err := store.Enqueue(ctx, job); err != nil {
			t.Fatal(err)
		}
		job.ID += "_duplicate"
		if err := store.Enqueue(ctx, job); err != nil {
			t.Fatal(err)
		}
	}
	// Hold one real row lock throughout competing claims. Other replicas must
	// drain all unlocked work without waiting for it or claiming it early.
	leader, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = leader.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := leader.Exec(ctx, `SELECT id FROM outbox_jobs WHERE id='job_00' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	ready := make(chan struct{}, replicas)
	errs := make(chan error, replicas)
	claims := make(chan postgres.ClaimedJob, jobs)
	for range replicas {
		replica, err := postgres.Open(ctx, pool.Config().ConnString())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(replica.Close)
		go func() {
			ready <- struct{}{}
			<-start
			for {
				batch, err := replica.ClaimJobs(ctx, 1)
				if err != nil || len(batch) == 0 {
					errs <- err
					return
				}
				job := batch[0]
				claims <- job
				if err := replica.CompleteJob(ctx, job.ID, job.LeaseToken); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	for range replicas {
		<-ready
	}
	close(start)
	for range replicas {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	close(claims)
	seen := map[string]bool{}
	for job := range claims {
		if job.ID == "job_00" || seen[job.ID] || job.Attempts != 1 || job.LeaseToken == "" || job.Payload["owner"] != job.TenantID {
			t.Fatal("worker duplicated a claim, lost tenant binding or bypassed row lock")
		}
		seen[job.ID] = true
	}
	if len(seen) != jobs-1 {
		t.Fatal("workers failed to drain unlocked jobs", len(seen))
	}
	if err := leader.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	last, err := store.ClaimJobs(ctx, 1)
	if err != nil || len(last) != 1 || last[0].ID != "job_00" || last[0].Attempts != 1 {
		t.Fatal("released row was not claimed exactly once", err)
	}
	if err := store.CompleteJob(ctx, last[0].ID, last[0].LeaseToken); err != nil {
		t.Fatal(err)
	}
	var completed, attempts int
	if err := pool.QueryRow(ctx, `SELECT(SELECT count(*) FROM outbox_jobs WHERE status='succeeded' AND attempts=1),(SELECT count(*) FROM outbox_job_attempts)`).Scan(&completed, &attempts); err != nil || completed != jobs || attempts != jobs*2 {
		t.Fatal("deduplication/claim/completion totals differ", completed, attempts, err)
	}
}
