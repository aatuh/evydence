package main

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	databaseURL := strings.TrimSpace(os.Getenv("EVYDENCE_DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("worker requires EVYDENCE_DATABASE_URL")
	}
	ctx := context.Background()
	store, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	if !strings.EqualFold(os.Getenv("EVYDENCE_SKIP_MIGRATIONS"), "true") {
		migrateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if _, err := store.ApplyMigrations(migrateCtx, envDefault("EVYDENCE_MIGRATIONS_DIR", "migrations")); err != nil {
			cancel()
			return err
		}
		cancel()
	}
	pollInterval := durationEnv("EVYDENCE_WORKER_POLL_INTERVAL", time.Second)
	batchSize := intEnv("EVYDENCE_WORKER_BATCH_SIZE", 10)
	log.Printf("evydence worker started with postgres outbox polling interval %s", pollInterval)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		jobs, err := store.ClaimJobs(ctx, batchSize)
		if err != nil {
			log.Printf("outbox claim failed: %v", err)
			time.Sleep(pollInterval)
			continue
		}
		if len(jobs) == 0 {
			time.Sleep(pollInterval)
			continue
		}
		for _, job := range jobs {
			log.Printf("processing outbox job id=%s kind=%s subject_type=%s subject_id=%s attempt=%d", job.ID, job.Kind, job.SubjectType, job.SubjectID, job.Attempts)
			if err := processJob(ctx, job); err != nil {
				log.Printf("outbox job failed id=%s kind=%s: %v", job.ID, job.Kind, err)
				if failErr := store.FailJob(ctx, job.ID, err); failErr != nil {
					log.Printf("record outbox failure failed id=%s: %v", job.ID, failErr)
				}
				continue
			}
			if err := store.CompleteJob(ctx, job.ID); err != nil {
				log.Printf("complete outbox job failed id=%s: %v", job.ID, err)
			}
		}
	}
}

func processJob(ctx context.Context, job postgres.ClaimedJob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch job.Kind {
	case "parse_sbom", "parse_vulnerability_scan", "parse_openapi_contract", "parse_vex", "sign_bundle", "verify_subject":
		return nil
	default:
		return errors.New("unsupported outbox job kind")
	}
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func intEnv(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
