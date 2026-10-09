package query

import (
	"errors"
	"testing"
	"time"
)

type paginationRecord struct {
	ID        string
	CreatedAt time.Time
}

func TestCursorPaginationProvidesStableContinuation(t *testing.T) {
	codec, err := NewCursorCodec([]byte("test-cursor-signing-secret"))
	if err != nil {
		t.Fatalf("NewCursorCodec: %v", err)
	}
	createdAt := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	records := []paginationRecord{
		{ID: "record-c", CreatedAt: createdAt.Add(time.Second)},
		{ID: "record-b", CreatedAt: createdAt},
		{ID: "record-a", CreatedAt: createdAt},
	}
	first, err := Page(records, PageRequest{PageSize: 2, Sort: SortCreatedAt, Direction: Ascending}, nil, func(record paginationRecord, sort Sort) SortKey {
		return RecordSortKey(record.ID, record.CreatedAt, sort)
	})
	if err != nil {
		t.Fatalf("Page first: %v", err)
	}
	if got := []string{first.Items[0].ID, first.Items[1].ID}; got[0] != "record-a" || got[1] != "record-b" {
		t.Fatalf("first page IDs = %#v, want record-a, record-b", got)
	}
	if first.Next == nil {
		t.Fatal("first page has no continuation cursor")
	}
	cursor, err := codec.Encode(Cursor{
		TenantID:  "tenant-a",
		Resource:  "products",
		Filters:   "filters-hash",
		Sort:      SortCreatedAt,
		Direction: Ascending,
		Key:       *first.Next,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := codec.Decode(cursor)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	second, err := Page(records, PageRequest{PageSize: 2, Sort: decoded.Sort, Direction: decoded.Direction}, &decoded.Key, func(record paginationRecord, sort Sort) SortKey {
		return RecordSortKey(record.ID, record.CreatedAt, sort)
	})
	if err != nil {
		t.Fatalf("Page second: %v", err)
	}
	if len(second.Items) != 1 || second.Items[0].ID != "record-c" {
		t.Fatalf("second page = %#v, want only record-c", second.Items)
	}
	if second.Next != nil {
		t.Fatalf("second page next = %#v, want nil", second.Next)
	}
}

func TestCursorCodecRejectsTampering(t *testing.T) {
	codec, err := NewCursorCodec([]byte("test-cursor-signing-secret"))
	if err != nil {
		t.Fatalf("NewCursorCodec: %v", err)
	}
	cursor, err := codec.Encode(Cursor{
		TenantID:  "tenant-a",
		Resource:  "evidence",
		Filters:   "filters-hash",
		Sort:      SortCreatedAt,
		Direction: Descending,
		Key:       SortKey{Value: "2026-08-22T10:00:00Z", ID: "ev_1"},
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	_, err = codec.Decode(cursor + "x")
	if !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("Decode(tampered) error = %v, want ErrInvalidCursor", err)
	}
}

func TestCursorPaginationSupportsDescendingIDOrderingAndRejectsInvalidRequests(t *testing.T) {
	codec, err := NewCursorCodec([]byte("test-cursor-signing-secret"))
	if err != nil {
		t.Fatalf("NewCursorCodec: %v", err)
	}
	if _, err := NewCursorCodec(nil); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("NewCursorCodec(nil) error = %v, want ErrInvalidCursor", err)
	}
	if _, err := codec.Encode(Cursor{}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("Encode(empty) error = %v, want ErrInvalidCursor", err)
	}
	if _, err := codec.Decode("not-a-cursor"); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("Decode(malformed) error = %v, want ErrInvalidCursor", err)
	}

	createdAt := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	records := []paginationRecord{{ID: "record-a", CreatedAt: createdAt}, {ID: "record-c", CreatedAt: createdAt.Add(time.Second)}, {ID: "record-b", CreatedAt: createdAt}}
	first, err := Page(records, PageRequest{PageSize: 2, Sort: SortID, Direction: Descending}, nil, func(record paginationRecord, sort Sort) SortKey {
		return RecordSortKey(record.ID, record.CreatedAt, sort)
	})
	if err != nil {
		t.Fatalf("Page descending ID: %v", err)
	}
	if got := []string{first.Items[0].ID, first.Items[1].ID}; got[0] != "record-c" || got[1] != "record-b" {
		t.Fatalf("descending page IDs = %#v, want record-c, record-b", got)
	}
	if first.Next == nil {
		t.Fatal("descending page has no continuation cursor")
	}
	second, err := Page(records, PageRequest{PageSize: 2, Sort: SortID, Direction: Descending}, first.Next, func(record paginationRecord, sort Sort) SortKey {
		return RecordSortKey(record.ID, record.CreatedAt, sort)
	})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != "record-a" {
		t.Fatalf("second descending page=%#v err=%v", second, err)
	}
	if err := Validate(PageRequest{PageSize: 0, Sort: SortID, Direction: Ascending}, nil); !errors.Is(err, ErrInvalidPage) {
		t.Fatalf("Validate(zero size) error = %v, want ErrInvalidPage", err)
	}
	if err := Validate(PageRequest{PageSize: 1, Sort: "unexpected", Direction: Ascending}, nil); !errors.Is(err, ErrInvalidPage) {
		t.Fatalf("Validate(sort) error = %v, want ErrInvalidPage", err)
	}
}
