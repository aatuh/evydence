package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// Transport fake: exercises repository decoding and statement shape, not live
// PostgreSQL row locks, ownership joins or pre-transfer bounds.
type customerAccessDecodeTx struct {
	pgx.Tx
	t         *testing.T
	manifest  []byte
	oversized bool
	fenced    bool
	cancel    context.CancelFunc
}

func (f *customerAccessDecodeTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if !strings.Contains(sql, "pg_advisory_xact_lock") || len(args) != 2 || args[1] != "tenant" {
		f.t.Fatal("access omitted tenant mutation fence")
	}
	f.fenced = true
	return pgconn.CommandTag{}, nil
}

func (f *customerAccessDecodeTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	if !f.fenced || len(args) != 3 || args[0] != "tenant" || args[1] != "package" || args[2] != packageapp.MaxCustomerPackageManifestBytes || !strings.Contains(sql, "FOR UPDATE OF p") || !strings.Contains(sql, "CASE WHEN octet_length(p.manifest::text)<=$3") {
		f.t.Fatal("selected package read lost lock order or byte guard")
	}
	return customerAccessDecodeRow{f}
}

type customerAccessDecodeRow struct{ tx *customerAccessDecodeTx }

func (r customerAccessDecodeRow) Scan(dest ...any) error {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	values := []any{"package", "tenant", "product", "release", "profile", "Review", "generated", r.tx.manifest, "sha256:fixture", now.Add(time.Hour), 4, "package.v1", now, r.tx.oversized}
	if len(dest) != len(values) {
		r.tx.t.Fatal("selected package row shape changed")
	}
	for i, v := range values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(v))
	}
	if r.tx.cancel != nil {
		r.tx.cancel()
	}
	return nil
}

func TestCustomerPackageAccessDecodePreservesFrozenExactNumbers(t *testing.T) {
	f := &customerAccessDecodeTx{t: t, manifest: []byte(`{"evidence_ids":["evidence"],"exact":9007199254740993,"nested":{"decimal":123456789.123456789}}`)}
	p, err := (packages{f}).GetCustomerSecurityPackageForUpdate(t.Context(), "tenant", "package")
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := p.Manifest["exact"].(json.Number); !ok || n.String() != "9007199254740993" {
		t.Fatal("frozen integer rounded", p.Manifest)
	}
	if n, ok := p.Manifest["nested"].(map[string]any)["decimal"].(json.Number); !ok || n.String() != "123456789.123456789" {
		t.Fatal("frozen decimal rounded", p.Manifest)
	}
}

func TestCustomerPackageAccessDecodeRejectsUnboundedOrMalformedManifestWithoutData(t *testing.T) {
	keys := make([]string, 4097)
	for i := range keys {
		keys[i] = fmt.Sprintf(`"k%d":null`, i)
	}
	for _, tc := range []struct {
		name, raw string
		oversized bool
	}{
		{"deep", `{"nested":` + strings.Repeat("[", 33) + "null" + strings.Repeat("]", 33) + "}", false},
		{"many-keys", "{" + strings.Join(keys, ",") + "}", false},
		{"many-items", `{"items":[` + strings.Repeat("null,", 4096) + "null]}", false},
		{"byte-limit", `{"large":"` + strings.Repeat("x", packageapp.MaxCustomerPackageManifestBytes) + `"}`, false},
		{"server-oversized", "{}", true},
		{"array", "[]", false}, {"null", "null", false}, {"trailing", "{}{}", false},
		{"duplicate-keys", `{"exact":1,"exact":2}`, false},
		{"malformed", "{", false}, {"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &customerAccessDecodeTx{t: t, manifest: []byte(tc.raw), oversized: tc.oversized}
			p, err := (packages{f}).GetCustomerSecurityPackageForUpdate(t.Context(), "tenant", "package")
			if !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(p, domain.CustomerSecurityPackage{}) {
				t.Fatal("invalid manifest returned package data", err)
			}
		})
	}
}

func TestCustomerPackageAccessDecodeHonorsCancellationAfterRowRead(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := &customerAccessDecodeTx{t: t, manifest: []byte("{}"), cancel: cancel}
	p, err := (packages{f}).GetCustomerSecurityPackageForUpdate(ctx, "tenant", "package")
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(p, domain.CustomerSecurityPackage{}) {
		t.Fatal("cancelled read returned data", err)
	}
}
