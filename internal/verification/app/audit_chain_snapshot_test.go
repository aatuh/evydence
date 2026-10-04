package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// Deliberately exposes only page reads: no lock, authorization, receipt,
// audit, outbox or transaction capability is available to the inspector.
type auditSnapshotPages struct {
	pages []AuditChainVerificationPage
	reads int
}

func (r *auditSnapshotPages) ReadAuditChainVerificationPage(context.Context, AuditChainVerificationView, *int64, int) (AuditChainVerificationPage, error) {
	i := r.reads
	r.reads++
	if i >= len(r.pages) {
		return AuditChainVerificationPage{}, nil
	}
	return r.pages[i], nil
}

func TestInspectAuditChainSnapshotNeedsOnlyReadCapability(t *testing.T) {
	c, f := auditVerificationFixture(t)
	r := &auditSnapshotPages{pages: f.pages}
	v, err := InspectAuditChainSnapshot(t.Context(), r, f.view, "tenant", c.config.Clock.Now(), c.config.Hasher, c.config.Verifier)
	want, wantErr := inspectAuditChainView(t.Context(), f, f.view, "tenant", c.config.Clock.Now(), c.config.Hasher, c.config.Verifier, nil)
	if err != nil || wantErr != nil || !reflect.DeepEqual(v, want) || r.reads != 2 || len(f.results)+len(f.audits)+len(f.jobs) != 0 {
		t.Fatalf("read-only inspection=%#v expected=%#v reads=%d err=%v/%v", v, want, r.reads, err, wantErr)
	}
	if v, err := InspectAuditChainSnapshot(t.Context(), &auditSnapshotPages{pages: f.pages}, f.view, "foreign", c.config.Clock.Now(), c.config.Hasher, c.config.Verifier); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, SubjectInspection{}) {
		t.Fatal("foreign snapshot returned inspection", v, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := InspectAuditChainSnapshot(ctx, r, f.view, "tenant", c.config.Clock.Now(), c.config.Hasher, c.config.Verifier); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, now := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := InspectAuditChainSnapshot(t.Context(), r, f.view, "tenant", now, c.config.Hasher, c.config.Verifier); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid generation clock", err)
		}
	}
	if _, err := InspectAuditChainSnapshot(t.Context(), r, f.view, "tenant", c.config.Clock.Now(), nil, c.config.Verifier); !errors.Is(err, ErrValidation) {
		t.Fatal("missing hasher", err)
	}
}
