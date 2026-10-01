package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type backupVerificationFake struct {
	bundleVerificationFake
	point BackupVerificationSnapshot
}

func (f *backupVerificationFake) ExecuteBackupVerification(ctx context.Context, fn func(context.Context, BackupVerificationTransaction) error) error {
	copy := *f
	copy.results, copy.audits, copy.jobs = nil, nil, nil
	err := fn(ctx, &copy)
	f.payloadReads = copy.payloadReads
	if err != nil {
		return err
	}
	if f.fail == "commit" {
		return errVerificationTestFailure
	}
	f.results, f.audits, f.jobs = copy.results, copy.audits, copy.jobs
	return nil
}
func (f *backupVerificationFake) ReadBackupVerification(context.Context, SubjectReference) (BackupVerificationSnapshot, error) {
	f.payloadReads++
	if f.fail == "read" {
		return BackupVerificationSnapshot{}, errVerificationTestFailure
	}
	return f.point, nil
}
func backupVerificationFixture(t *testing.T) (*BackupVerificationCommands, *backupVerificationFake) {
	t.Helper()
	c, base := bundleVerificationFixture(t)
	f := &backupVerificationFake{bundleVerificationFake: *base, point: BackupVerificationSnapshot{Subject: SubjectReference{TenantID: "tenant", Type: "backup_manifest", ID: "backup"}, StateHash: "sha256:backup", Checks: []verificationdomain.VerifyCheck{{Name: "audit_chain", Result: "passed"}, {Name: "sequence", Result: "passed", Detail: "entry"}}}}
	command, err := NewBackupVerificationCommands(BackupVerificationConfig{Transactions: f, Authorizer: f, Clock: c.config.Clock, IDs: c.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return command, f
}
func TestBackupVerificationPreservesRecordedProfileAndAtomicReceipt(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	c, f := backupVerificationFixture(t)
	r, err := c.VerifyBackupManifest(t.Context(), actor, "backup")
	if err != nil || r.Result.String() != "passed" || r.SubjectType != "backup_manifest" || r.SubjectID != "backup" || r.Profile.ID != verificationdomain.VerificationProfileBackupManifest || r.Profile.PayloadDigest != "sha256:backup" || r.Profile.TransparencyProof != "not_evaluated" || len(r.Checks) != 3 || r.Checks[2].Name != "backup_manifest_present" || r.Checks[2].Detail != "sha256:backup" || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 {
		t.Fatal(r, err, f)
	}
	for _, failure := range []string{"read", "result", "audit", "outbox", "commit"} {
		c, f = backupVerificationFixture(t)
		f.fail = failure
		r, err = c.VerifyBackupManifest(t.Context(), actor, "backup")
		if !errors.Is(err, errVerificationTestFailure) || r.ID != "" || len(f.results)+len(f.audits)+len(f.jobs) != 0 {
			t.Fatal(failure, r, err)
		}
	}
	c, f = backupVerificationFixture(t)
	f.fail = "auth"
	if _, err := c.VerifyBackupManifest(t.Context(), actor, "backup"); !errors.Is(err, application.ErrForbidden) || f.payloadReads != 0 {
		t.Fatal("read before authorization", err)
	}
	c, f = backupVerificationFixture(t)
	f.point.Subject.TenantID = "foreign"
	if _, err := c.VerifyBackupManifest(t.Context(), actor, "backup"); !errors.Is(err, ErrNotFound) || len(f.results) != 0 {
		t.Fatal("foreign receipt", err)
	}
	for _, id := range []string{"", " ", "bad\x00id", string([]byte{255}), strings.Repeat("x", 1025)} {
		c, f = backupVerificationFixture(t)
		if _, err := c.VerifyBackupManifest(t.Context(), actor, id); !errors.Is(err, ErrValidation) || f.payloadReads != 0 {
			t.Fatal("invalid ID", err)
		}
	}
	c, f = backupVerificationFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.VerifyBackupManifest(ctx, actor, "backup"); !errors.Is(err, context.Canceled) || f.payloadReads != 0 {
		t.Fatal(err)
	}
}
func TestBackupVerificationAggregatesOnlyRecordedChecks(t *testing.T) {
	for _, state := range []string{"passed", "failed", "limited", "error", "skipped", "not_verified"} {
		c, f := backupVerificationFixture(t)
		f.point.Checks[0].Result = state
		r, err := c.VerifyBackupManifest(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "backup")
		want := state
		if state == "skipped" || state == "not_verified" {
			want = "limited"
		}
		if r.Result.String() != want || r.Checks[0].Result != state || len(f.results) != 1 {
			t.Fatal(state, r, err)
		}
		if (state == "failed" || state == "error") != errors.Is(err, ErrVerificationFailed) {
			t.Fatal(state, err)
		}
	}
	for name, mutate := range map[string]func(*BackupVerificationSnapshot){
		"check count": func(s *BackupVerificationSnapshot) {
			s.Checks = make([]verificationdomain.VerifyCheck, MaxBackupVerificationChecks+1)
		},
		"state hash":   func(s *BackupVerificationSnapshot) { s.StateHash = strings.Repeat("x", 1025) },
		"name":         func(s *BackupVerificationSnapshot) { s.Checks[0].Name = " " },
		"result":       func(s *BackupVerificationSnapshot) { s.Checks[0].Result = "" },
		"detail":       func(s *BackupVerificationSnapshot) { s.Checks[0].Detail = strings.Repeat("x", 1025) },
		"invalid text": func(s *BackupVerificationSnapshot) { s.Checks[0].Detail = "private\x00value" },
		"encoded budget": func(s *BackupVerificationSnapshot) {
			s.Checks = make([]verificationdomain.VerifyCheck, MaxBackupVerificationChecks)
			for i := range s.Checks {
				s.Checks[i] = verificationdomain.VerifyCheck{Name: "recorded", Result: "passed", Detail: strings.Repeat("\n", 1024)}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, f := backupVerificationFixture(t)
			mutate(&f.point)
			r, err := c.VerifyBackupManifest(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "backup")
			if !errors.Is(err, ErrConflict) || r.ID != "" || len(f.results) != 0 {
				t.Fatal(r, err)
			}
		})
	}
	c, f := backupVerificationFixture(t)
	f.point.Checks = nil
	r, err := c.VerifyBackupManifest(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "backup")
	if err != nil || len(r.Checks) != 1 || len(r.Profile.RequiredChecks) != 1 {
		t.Fatal("presence-only legacy record", r, err)
	}
}
