package postgres

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func TestOutboxDeadLettersPostgresBoundedPageSurvivesReplay(t *testing.T) {
	f := newMigrationRoleFixture(t, true)
	if _, err := f.migrator.ApplyMigrations(f.ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	if err := f.profile(f.ctx, f.migrator, f.runtime); err != nil {
		t.Fatal(err)
	}
	store, err := OpenPrepared(f.ctx, PreparedPoolConfig{config: f.application.pool.Config()}, StoreOptions{LoadMode: LoadModeRelationalOnly, DisableSnapshotWrites: true})
	if err != nil {
		t.Fatal("cannot open owned runtime role for dead-letter inspection")
	}
	defer store.Close()
	var identity, schema string
	if err := store.pool.QueryRow(f.ctx, "SELECT session_user,current_schema()").Scan(&identity, &schema); err != nil || identity != f.runtime || schema != f.schema {
		t.Fatal("dead-letter probe lost the dedicated runtime identity or quoted schema")
	}
	if _, err := f.migrator.pool.Exec(f.ctx, `INSERT INTO tenants(id,name)VALUES('tenant_a','First'),('tenant_b','Second')`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.migrator.pool.Exec(f.ctx, `INSERT INTO outbox_jobs(id,tenant_id,kind,subject_type,subject_id,payload,status,deduplication_key)
 SELECT 'job_0_queued_'||lpad(n::text,5,'0'),'tenant_a','parse_sbom','evidence','PRIVATE_SUBJECT','{"secret":"PRIVATE_PAYLOAD"}'::jsonb,'queued','queued_'||n FROM generate_series(1,5000)n`); err != nil {
		t.Fatal(err)
	}
	ids := []string{"job-1", "job_1", "job_a", "job_é"}
	for i, id := range ids {
		tenant := "tenant_a"
		if i%2 == 1 {
			tenant = "tenant_b"
		}
		if _, err := f.migrator.pool.Exec(f.ctx, `INSERT INTO outbox_jobs(id,tenant_id,kind,subject_type,subject_id,payload,status,attempts,max_attempts,deduplication_key,failure_class,failure_code,last_error,terminal_at)
 VALUES($1,$2,'parse_sbom','evidence','PRIVATE_SUBJECT','{"secret":"PRIVATE_PAYLOAD"}'::jsonb,'dead_letter',2,5,$1,'permanent','invalid_document','PRIVATE_RAW_ERROR',now())`, id, tenant); err != nil {
			t.Fatal(err)
		}
	}
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Ascending}
	first, err := store.ReadOutboxDeadLettersPage(f.ctx, page, nil)
	if err != nil || len(first.Items) != 2 || first.Items[0].ID != ids[0] || first.Items[1].ID != ids[1] || first.Next == nil || first.Next.ID != ids[1] {
		t.Fatal("indexed dead-letter page lost status filtering or byte ordering", err)
	}
	raw, err := json.Marshal(first)
	if err != nil || strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "tenant_") {
		t.Fatal("dead-letter projection exposed private operational columns")
	}
	replay, err := store.ReplayTerminalJob(f.ctx, ids[1], "instance_operator")
	if err != nil || replay.JobID != ids[1] || replay.Status != "queued" {
		t.Fatal("owned runtime could not replay the page anchor", err)
	}
	second, err := store.ReadOutboxDeadLettersPage(f.ctx, page, first.Next)
	if err != nil || len(second.Items) != 2 || second.Items[0].ID != ids[2] || second.Items[1].ID != ids[3] || second.Next != nil {
		t.Fatal("replayed anchor broke continuation or fabricated a next page", err)
	}
	page.Direction = appquery.Descending
	descending, err := store.ReadOutboxDeadLettersPage(f.ctx, page, nil)
	if err != nil || len(descending.Items) != 2 || descending.Items[0].ID != ids[3] || descending.Items[1].ID != ids[2] || descending.Next == nil {
		t.Fatal("descending dead-letter page lost byte ordering", err)
	}
	// Inspect the exact production statement, including its bound seek, without
	// disabling sequential scans or changing planner settings.
	if _, err := f.migrator.pool.Exec(f.ctx, "ANALYZE outbox_jobs"); err != nil {
		t.Fatal(err)
	}
	statement, args, err := outboxDeadLetterPageSQL(page, descending.Next)
	if err != nil {
		t.Fatal(err)
	}
	var plan []byte
	if err := store.pool.QueryRow(f.ctx, "EXPLAIN (FORMAT JSON) "+statement, args...).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan), `"Index Name": "outbox_jobs_dead_letter_id_idx"`) {
		t.Fatal("representative selective seek did not use the dead-letter index")
	}
	for _, value := range []string{"PRIVATE raw error", strings.Repeat("x", 100000)} {
		if _, err := f.migrator.pool.Exec(f.ctx, "UPDATE outbox_jobs SET failure_code=$1 WHERE id=$2", value, ids[2]); err != nil {
			t.Fatal(err)
		}
		result, err := store.ReadOutboxDeadLettersPage(f.ctx, page, nil)
		if !errors.Is(err, operationsquery.ErrInvalidProjection) || len(result.Items) != 0 || result.Next != nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("unsafe or oversized stored metadata exposed a partial page", err)
		}
	}
}

func TestOutboxDeadLetterLookupMigrationPreservesJobs(t *testing.T) {
	f := newMigrationRoleFixture(t, false)
	if _, err := f.migrator.ApplyMigrations(f.ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.migrator.pool.Exec(f.ctx, `INSERT INTO tenants(id,name)VALUES('lookup_tenant','Lookup preservation')`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.migrator.pool.Exec(f.ctx, `INSERT INTO outbox_jobs(id,tenant_id,kind,subject_type,subject_id,payload,status,deduplication_key)
 SELECT 'preserve_'||n,'lookup_tenant','parse_sbom','evidence','kept','{"kept":true}'::jsonb,'queued','preserve_'||n FROM generate_series(1,2)n`); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := f.migrator.pool.QueryRow(f.ctx, "SELECT count(*) FROM outbox_jobs").Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"down", "up"} {
		body, err := os.ReadFile("../../../migrations/20261104000200_outbox_dead_letter_lookup." + suffix + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.migrator.pool.Exec(f.ctx, string(body)); err != nil {
			t.Fatal(err)
		}
	}
	var after int
	var kept bool
	var identifiers string
	if err := f.migrator.pool.QueryRow(f.ctx, `SELECT count(*),bool_and(payload='{"kept":true}'::jsonb AND status='queued' AND subject_id='kept'),string_agg(id,',' ORDER BY id) FROM outbox_jobs`).Scan(&after, &kept, &identifiers); err != nil || before != 2 || before != after || !kept || identifiers != "preserve_1,preserve_2" {
		t.Fatal("lookup index migration changed jobs")
	}
	var definition string
	if err := f.migrator.pool.QueryRow(f.ctx, "SELECT pg_catalog.pg_get_indexdef(pg_catalog.to_regclass('outbox_jobs_dead_letter_id_idx'))").Scan(&definition); err != nil || !strings.Contains(definition, `COLLATE "C"`) || !strings.Contains(definition, "dead_letter") {
		t.Fatal("lookup index lost its collation or terminal predicate", err)
	}
}

func TestOutboxDeadLetterStatementRejectsInvalidInputs(t *testing.T) {
	for _, page := range []appquery.PageRequest{{}, {PageSize: 501, Sort: appquery.SortID, Direction: appquery.Ascending}, {PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}} {
		statement, args, err := outboxDeadLetterPageSQL(page, nil)
		if !errors.Is(err, operationsquery.ErrValidation) || statement != "" || len(args) != 0 {
			t.Fatal("invalid keyset input produced executable SQL")
		}
	}
	page := appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Ascending}
	key := appquery.SortKey{Value: "id'quoted", ID: "id'quoted"}
	statement, args, err := outboxDeadLetterPageSQL(page, &key)
	if err != nil || strings.Contains(statement, key.ID) || !slices.ContainsFunc(args, func(value any) bool { return value == key.ID }) {
		t.Fatal("keyset ID was not supplied as a bound value", err)
	}
}
