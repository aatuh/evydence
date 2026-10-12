package app

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type alteredStagingStore struct {
	*testObjectStore
	mutate func(*ObjectPayload)
}

func (s alteredStagingStore) StagePayload(ctx context.Context, p ObjectPayload, r io.Reader) (ObjectPayload, error) {
	v, err := s.testObjectStore.StagePayload(ctx, p, r)
	if err == nil && s.mutate != nil {
		s.mutate(&v)
	}
	return v, err
}

func TestStageObjectPayloadVerifiesAllRequestedBindingsWithoutFinalizing(t *testing.T) {
	at := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	for _, mutate := range []func(*ObjectPayload){nil,
		func(p *ObjectPayload) { p.TenantID = "other" },
		func(p *ObjectPayload) { p.Digest = sampleDigest("other") },
		func(p *ObjectPayload) { p.Size++ },
		func(p *ObjectPayload) { p.MediaType = "application/pdf" },
		func(p *ObjectPayload) { p.StagingKey = "foreign-staging" },
		func(p *ObjectPayload) { p.FinalKey = "foreign-final" },
		func(p *ObjectPayload) { p.CreatedAt = p.CreatedAt.Add(time.Second) },
		func(p *ObjectPayload) { p.UpdatedAt = time.Time{} },
		func(p *ObjectPayload) { p.Status = ObjectPayloadFinalized },
	} {
		objects := alteredStagingStore{newTestObjectStore(), mutate}
		p, err := StageObjectPayload(t.Context(), objects, "tenant", "application/json", BytesPayloadSource([]byte(`{"raw":true}`)), at)
		if mutate != nil {
			if !errors.Is(err, ErrValidation) || p != (ObjectPayload{}) {
				t.Fatal("untrusted staging metadata accepted", p, err)
			}
			continue
		}
		if err != nil || p.Status != ObjectPayloadStaged || p.Size != 12 || p.CreatedAt != at {
			t.Fatal(p, err)
		}
		if _, err := objects.Get(t.Context(), p.StagingKey); err != nil {
			t.Fatal(err)
		}
		if _, err := objects.Get(t.Context(), p.FinalKey); !errors.Is(err, ErrNotFound) {
			t.Fatal("premature finalization", err)
		}
	}
}

func TestStageObjectPayloadRejectsMissingSourceWithoutPanic(t *testing.T) {
	source := BytesPayloadSource([]byte("payload"))
	source.Open = func() (io.ReadCloser, error) { return nil, nil }
	if _, err := StageObjectPayload(t.Context(), newTestObjectStore(), "tenant", "application/json", source, time.Now()); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}
