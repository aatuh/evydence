package repositories

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// BackupCommitmentProfileResources returns a fresh copy of the declared profile
// so tooling can reproduce commitments and check migration coverage.
func BackupCommitmentProfileResources() []verificationapp.BackupCommitmentResource {
	sources := BackupCommitmentProfileResourcesV1()
	sources = append(sources, verificationapp.BackupCommitmentResource{Name: "vulnerability_decision_supersessions", Columns: []string{"tenant_id", "finding_id", "predecessor_id", "successor_id", "created_at", "schema_version"}})
	sort.Slice(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })
	return sources
}

// BackupCommitmentProfileResourcesV1 retains the original allowlist for
// historical commitment reproduction; v2 adds durable decision relationships.
func BackupCommitmentProfileResourcesV1() []verificationapp.BackupCommitmentResource {
	var sources []verificationapp.BackupCommitmentResource
	for _, line := range strings.Split(strings.TrimSpace(backupCommitmentCatalog), "\n") {
		name, columns, _ := strings.Cut(line, "|")
		sources = append(sources, verificationapp.BackupCommitmentResource{Name: name, Columns: strings.Split(columns, ",")})
	}
	return sources
}

func (r integrity) ReadBackupStateCommitment(ctx context.Context, tenant string) (verificationapp.BackupStateCommitment, error) {
	var empty verificationapp.BackupStateCommitment
	// Fence tenant changes without blocking the projection-owning worker's
	// foreign-key checks while we wait for its projection lock.
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return empty, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return empty, err
	}
	if _, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenant); err != nil {
		return empty, err
	}
	if _, err := r.tx.Exec(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return empty, err
	}
	sources := BackupCommitmentProfileResources()
	digester, err := verificationapp.NewBackupStateDigester(tenant, sources)
	if err != nil {
		return empty, err
	}
	var arms []string
	for _, source := range sources {
		columns := make([]string, len(source.Columns))
		for i, column := range source.Columns {
			columns[i] = pgx.Identifier{column}.Sanitize()
		}
		table := pgx.Identifier{source.Name}.Sanitize()
		predicate := `tenant_id=$1`
		key := `id`
		from := table
		switch source.Name {
		case "tenants":
			predicate = `id=$1`
		case "tenant_audit_sequences":
			key = `tenant_id`
		case "vulnerability_decision_supersessions":
			key = `predecessor_id`
		case "object_payloads":
			key = `object_key`
		case "outbox_job_attempts":
			from = `(SELECT a.id,j.tenant_id,a.job_id,a.attempt,a.outcome,a.failure_class,a.failure_code,a.occurred_at FROM outbox_job_attempts a JOIN outbox_jobs j ON j.id=a.job_id) attempts`
		}
		// All identifiers come exclusively from the fixed profile above; only
		// tenant, row cap and byte cap are bind parameters, never SQL text.
		arms = append(arms, fmt.Sprintf(`(SELECT '%s'::text resource,row_key,to_jsonb(selected)-'row_key' body FROM (SELECT (%s)::text AS row_key,%s FROM %s WHERE %s ORDER BY (%s)::text COLLATE "C" LIMIT $2) selected)`, source.Name, key, strings.Join(columns, ","), from, predicate, key))
	}
	// One SQL statement supplies one MVCC view across every profile resource.
	// Its +1 sentinel rejects incomplete prefixes, including per-table overflow.
	statement := `SELECT resource,left(row_key,4097),CASE WHEN octet_length(row_key)<=4096 AND octet_length(body::text)<=$3 THEN body ELSE NULL END FROM (` + strings.Join(arms, ` UNION ALL `) + `) committed ORDER BY resource COLLATE "C",row_key COLLATE "C" LIMIT $2`
	rows, err := r.tx.Query(ctx, statement, tenant, verificationapp.MaxBackupStateCommitmentRows+1, verificationapp.MaxBackupStateCommitmentBytes)
	if err != nil {
		return empty, fmt.Errorf("read backup state commitment: %w", err)
	}
	defer rows.Close()
	counts := map[string]int{"audit_chain_entries": 0, "artifact_signatures": 0, "cosign_verifications": 0, "evidence": 0, "merkle_batches": 0, "object_retention_policies": 0, "release_bundles": 0, "transparency_checkpoints": 0}
	for rows.Next() {
		var resource, key string
		var body []byte
		if err := rows.Scan(&resource, &key, &body); err != nil {
			return empty, err
		}
		if err := digester.Append(resource, key, body); err != nil {
			return empty, app.ErrConflict
		}
		name := resource
		if name == "evidence_items" {
			name = "evidence"
		}
		if _, ok := counts[name]; ok {
			counts[name]++
		}
	}
	if err := rows.Err(); err != nil {
		return empty, err
	}
	hash, count, bytes, err := digester.Finish()
	if err != nil {
		return empty, app.ErrConflict
	}
	return verificationapp.BackupStateCommitment{TenantID: tenant, Profile: verificationapp.BackupStateCommitmentProfile, StateHash: hash, ResourceCounts: counts, RowsRead: count, BytesRead: bytes}, nil
}
