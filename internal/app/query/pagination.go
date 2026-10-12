// Package query contains transport-neutral bounded query primitives.
package query

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

const (
	DefaultPageSize = 50
	// MaxPageSize retains the historical 500-record ceiling used by the
	// established audit, search, and SBOM collection routes. It is a hard
	// transport boundary; clients should normally use the 50-record default.
	MaxPageSize = 500

	cursorVersion  = 1
	maxCursorBytes = 4096
)

var (
	// ErrInvalidCursor deliberately has no parsing detail so callers can map all
	// malformed, forged, expired-format, and mismatched cursor tokens safely.
	ErrInvalidCursor = errors.New("invalid cursor")
	ErrInvalidPage   = errors.New("invalid page request")
)

type Sort string

const (
	SortCreatedAt Sort = "created_at"
	SortID        Sort = "id"
)

type Direction string

const (
	Ascending  Direction = "asc"
	Descending Direction = "desc"
)

// SortKey is the stable tuple used for cursor pagination. ID always breaks
// ties, including when the requested sort itself is ID.
type SortKey struct {
	Value string `json:"value"`
	ID    string `json:"id"`
}

// Cursor is deliberately resource, tenant, filter, and ordering bound. A
// token that belongs to one list request is never valid for another one.
type Cursor struct {
	Version   int       `json:"v"`
	TenantID  string    `json:"t"`
	Resource  string    `json:"r"`
	Filters   string    `json:"f"`
	Sort      Sort      `json:"s"`
	Direction Direction `json:"d"`
	Key       SortKey   `json:"k"`
}

// CursorCodec makes a compact opaque, authenticated token. It authenticates
// cursor state but does not treat cursors as secrets: only public sort keys are
// encoded and all authorization remains server-side.
type CursorCodec struct {
	secret []byte
}

func NewCursorCodec(secret []byte) (CursorCodec, error) {
	if len(secret) < 16 {
		return CursorCodec{}, ErrInvalidCursor
	}
	key := make([]byte, len(secret))
	copy(key, secret)
	return CursorCodec{secret: key}, nil
}

func (c CursorCodec) Encode(cursor Cursor) (string, error) {
	if len(c.secret) == 0 {
		return "", ErrInvalidCursor
	}
	cursor.Version = cursorVersion
	if !validCursor(cursor) {
		return "", ErrInvalidCursor
	}
	payload, err := json.Marshal(cursor)
	if err != nil || len(payload) > maxCursorBytes {
		return "", ErrInvalidCursor
	}
	mac := hmac.New(sha256.New, c.secret)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (c CursorCodec) Decode(raw string) (Cursor, error) {
	if len(c.secret) == 0 || len(raw) == 0 || len(raw) > maxCursorBytes {
		return Cursor{}, ErrInvalidCursor
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Cursor{}, ErrInvalidCursor
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > maxCursorBytes {
		return Cursor{}, ErrInvalidCursor
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size {
		return Cursor{}, ErrInvalidCursor
	}
	mac := hmac.New(sha256.New, c.secret)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return Cursor{}, ErrInvalidCursor
	}
	var cursor Cursor
	if err := json.Unmarshal(payload, &cursor); err != nil || !validCursor(cursor) {
		return Cursor{}, ErrInvalidCursor
	}
	return cursor, nil
}

func validCursor(cursor Cursor) bool {
	return cursor.Version == cursorVersion && validBoundedString(cursor.TenantID) && validBoundedString(cursor.Resource) && validBoundedString(cursor.Filters) && validSort(cursor.Sort) && validDirection(cursor.Direction) && validBoundedString(cursor.Key.Value) && validBoundedString(cursor.Key.ID)
}

func validBoundedString(value string) bool {
	return value != "" && len(value) <= 1024
}

type PageRequest struct {
	PageSize  int
	Sort      Sort
	Direction Direction
}

type Result[T any] struct {
	Items []T
	Next  *SortKey
}

// Page orders items in place and returns at most PageSize records. Sorting the
// caller's request-scoped slice avoids a second tenant-sized allocation. SQL
// adapters use the same key semantics with indexed keyset predicates.
func Page[T any](items []T, request PageRequest, after *SortKey, keyOf func(T, Sort) SortKey) (Result[T], error) {
	if err := Validate(request, after); err != nil || keyOf == nil {
		if err != nil {
			return Result[T]{}, err
		}
		return Result[T]{}, ErrInvalidPage
	}
	for _, item := range items {
		key := keyOf(item, request.Sort)
		if !validBoundedString(key.Value) || !validBoundedString(key.ID) {
			return Result[T]{}, ErrInvalidPage
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		left := keyOf(items[i], request.Sort)
		right := keyOf(items[j], request.Sort)
		comparison := compare(left, right)
		if request.Direction == Descending {
			return comparison > 0
		}
		return comparison < 0
	})
	start := 0
	if after != nil {
		found := false
		for start < len(items) {
			comparison := compare(keyOf(items[start], request.Sort), *after)
			if comparison == 0 {
				found = true
			}
			if (request.Direction == Ascending && comparison > 0) || (request.Direction == Descending && comparison < 0) {
				break
			}
			start++
		}
		if !found {
			return Result[T]{}, ErrInvalidCursor
		}
	}
	end := start + request.PageSize
	if end > len(items) {
		end = len(items)
	}
	result := Result[T]{Items: items[start:end]}
	if end < len(items) && end > start {
		next := keyOf(items[end-1], request.Sort)
		result.Next = &next
	}
	return result, nil
}

// Validate applies the shared transport-neutral bounds before either an
// in-memory fallback or a database adapter performs a page query.
func Validate(request PageRequest, after *SortKey) error {
	if request.PageSize < 1 || request.PageSize > MaxPageSize || !validSort(request.Sort) || !validDirection(request.Direction) {
		return ErrInvalidPage
	}
	if after != nil && (!validBoundedString(after.Value) || !validBoundedString(after.ID)) {
		return ErrInvalidCursor
	}
	return nil
}

func compare(left, right SortKey) int {
	if left.Value < right.Value {
		return -1
	}
	if left.Value > right.Value {
		return 1
	}
	if left.ID < right.ID {
		return -1
	}
	if left.ID > right.ID {
		return 1
	}
	return 0
}

// RecordSortKey standardizes the common ID/creation-time key semantics used
// by ledger records and prevents format drift between memory and SQL adapters.
func RecordSortKey(id string, createdAt time.Time, sort Sort) SortKey {
	switch sort {
	case SortCreatedAt:
		return SortKey{Value: createdAt.UTC().Format(time.RFC3339Nano), ID: id}
	case SortID:
		return SortKey{Value: id, ID: id}
	default:
		return SortKey{}
	}
}

func validSort(sort Sort) bool {
	return sort == SortCreatedAt || sort == SortID
}

func validDirection(direction Direction) bool {
	return direction == Ascending || direction == Descending
}
