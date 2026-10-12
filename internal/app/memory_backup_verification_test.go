package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type memoryBackupVerificationReader interface {
	verificationapp.BackupVerificationReader
	LockBackupVerificationScope(context.Context, string, string) error
}

func TestMemoryBackupVerificationAcceptsExactEncodedBudgetAndRejectsOneByteMore(t *testing.T) {
	tx, r, subject := memoryBackupVerificationFixture(t)
	full := verificationdomain.VerifyCheck{Name: "recorded", Result: "passed", Detail: strings.Repeat("<", 1024)}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	// Fill whole rows, then use one bounded escaped detail and the hash to
	// reach the exact combined JSON+hash budget without oversizing any field.
	count := (verificationapp.MaxBackupVerificationBytes - 3) / (len(raw) + 1)
	checks := make([]verificationdomain.VerifyCheck, count)
	for i := range checks {
		checks[i] = full
	}
	left := verificationapp.MaxBackupVerificationBytes - (2 + count*len(raw) + count - 1)
	if left > 1024 {
		last := verificationdomain.VerifyCheck{Name: "recorded", Result: "passed"}
		base, err := json.Marshal(last)
		if err != nil {
			t.Fatal(err)
		}
		last.Detail = strings.Repeat("<", (left-1024-len(base)-1+5)/6)
		checks = append(checks, last)
	}
	encoded, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	stored := tx.state.BackupManifests[subject.ID]
	stored.StateHash = strings.Repeat("h", verificationapp.MaxBackupVerificationBytes-len(encoded))
	stored.ConsistencyChecks = make([]domain.VerifyCheck, len(checks))
	for i, c := range checks {
		stored.ConsistencyChecks[i] = domain.VerifyCheck(c)
	}
	if len(stored.StateHash) < 1 || len(stored.StateHash) > 1024 || len(checks[len(checks)-1].Detail) >= 1024 {
		t.Fatal("exact-budget fixture cannot isolate the combined-byte boundary")
	}
	tx.state.BackupManifests[subject.ID] = stored
	if v, err := r.ReadBackupVerification(t.Context(), subject); err != nil || len(v.Checks) != len(checks) || v.StateHash != stored.StateHash {
		t.Fatal("exact combined encoded budget was rejected", err)
	}
	stored.ConsistencyChecks[len(checks)-1].Detail += "x"
	tx.state.BackupManifests[subject.ID] = stored
	if v, err := r.ReadBackupVerification(t.Context(), subject); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, verificationapp.BackupVerificationSnapshot{}) {
		t.Fatal("one-byte-over backup budget returned partial facts", err)
	}
}

func memoryBackupVerificationFixture(t *testing.T) (*memoryUnitOfWork, memoryBackupVerificationReader, verificationapp.SubjectReference) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Verification.(memoryBackupVerificationReader)
	if !ok {
		t.Fatal("memory verification lacks focused backup facts/identity ports")
	}
	tx.state.BackupManifests["backup"] = domain.BackupManifest{ID: "backup", TenantID: "tenant", StateHash: "sha256:recorded", ConsistencyChecks: []domain.VerifyCheck{{Name: "recorded_chain", Result: "failed", Detail: "recorded mismatch"}}, ResourceCounts: map[string]int{"ignored": 9}, Limitations: []string{"unselected-private-marker"}, SchemaVersion: domain.BackupManifestSchemaVersion, CreatedAt: fixedNow()}
	return tx, r, verificationapp.SubjectReference{TenantID: "tenant", Type: "backup_manifest", ID: "backup"}
}

func TestMemoryBackupVerificationReadsOnlyCurrentDetachedRecordedFacts(t *testing.T) {
	tx, r, subject := memoryBackupVerificationFixture(t)
	v, err := r.ReadBackupVerification(t.Context(), subject)
	if err != nil || v.Subject != subject || v.StateHash != "sha256:recorded" || len(v.Checks) != 1 || v.Checks[0].Result != "failed" {
		t.Fatal("backup read lost selected recorded facts", err)
	}
	raw, err := json.Marshal(v)
	if err != nil || strings.Contains(string(raw), "unselected-private-marker") || strings.Contains(string(raw), "ignored") {
		t.Fatal("backup verification selected full manifest metadata", err)
	}
	v.Checks[0].Detail = "caller"
	if tx.state.BackupManifests[subject.ID].ConsistencyChecks[0].Detail != "recorded mismatch" {
		t.Fatal("backup verification checks alias stored facts")
	}
	stored := tx.state.BackupManifests[subject.ID]
	stored.ConsistencyChecks = []domain.VerifyCheck{}
	tx.state.BackupManifests[subject.ID] = stored
	empty, err := r.ReadBackupVerification(t.Context(), subject)
	if err != nil || len(empty.Checks) != 0 {
		t.Fatal("historical empty recorded checks were rejected", err)
	}
	inspection, err := verificationapp.InspectBackupManifestRecordedChecks(empty)
	if err != nil || len(inspection.Checks) != 1 || inspection.Checks[0].Name != "backup_manifest_present" || inspection.Checks[0].Result != "passed" {
		t.Fatal("empty checks lost historical presence-only receipt", err)
	}
	stored.StateHash = strings.Repeat("x", 1025)
	tx.state.BackupManifests[subject.ID] = stored
	if err := r.LockBackupVerificationScope(t.Context(), "tenant", subject.ID); err != nil {
		t.Fatal("backup replay inspected state hash", err)
	}
	if v, err := r.ReadBackupVerification(t.Context(), subject); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, verificationapp.BackupVerificationSnapshot{}) {
		t.Fatal("oversized backup hash returned partial facts", err)
	}
	tx.state.BackupManifests["foreign"] = domain.BackupManifest{ID: "foreign", TenantID: "foreign"}
	if err := r.LockBackupVerificationScope(t.Context(), "tenant", "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign backup authorized", err)
	}
	foreign := subject
	foreign.ID = "foreign"
	if v, err := r.ReadBackupVerification(t.Context(), foreign); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, verificationapp.BackupVerificationSnapshot{}) {
		t.Fatal("foreign backup returned recorded facts", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.ReadBackupVerification(ctx, subject); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, verificationapp.BackupVerificationSnapshot{}) {
		t.Fatal("cancelled backup verification returned facts", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.LockBackupVerificationScope(t.Context(), "tenant", subject.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("closed backup identity port accepted", err)
	}
}

func TestMemoryBackupVerificationRejectsInvalidAndOversizedCheckProjectionsWithoutPartialFacts(t *testing.T) {
	for name, mutate := range map[string]func(*domain.BackupManifest){
		"null-checks": func(p *domain.BackupManifest) { p.ConsistencyChecks = nil },
		"too-many-checks": func(p *domain.BackupManifest) {
			p.ConsistencyChecks = make([]domain.VerifyCheck, verificationapp.MaxBackupVerificationChecks+1)
		},
		"oversized-detail": func(p *domain.BackupManifest) { p.ConsistencyChecks[0].Detail = strings.Repeat("x", 1025) },
		"encoded-budget": func(p *domain.BackupManifest) {
			p.ConsistencyChecks = make([]domain.VerifyCheck, verificationapp.MaxBackupVerificationChecks)
			for i := range p.ConsistencyChecks {
				p.ConsistencyChecks[i] = domain.VerifyCheck{Name: strings.Repeat("n", 128), Result: "passed", Detail: strings.Repeat(`"`, 1024)}
			}
		},
		"incoherent-id": func(p *domain.BackupManifest) { p.ID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			tx, r, subject := memoryBackupVerificationFixture(t)
			stored := tx.state.BackupManifests[subject.ID]
			mutate(&stored)
			tx.state.BackupManifests[subject.ID] = stored
			if v, err := r.ReadBackupVerification(t.Context(), subject); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, verificationapp.BackupVerificationSnapshot{}) {
				t.Fatal("invalid backup projection returned partial facts", err)
			}
		})
	}
}
