package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type buildAttestationDecodeQuery struct{ raw []byte }

func (q buildAttestationDecodeQuery) QueryRow(context.Context, string, ...any) pgx.Row {
	return buildAttestationDecodeRow(q)
}

type buildAttestationDecodeRow buildAttestationDecodeQuery

func (r buildAttestationDecodeRow) Scan(dest ...any) error {
	if len(dest) != 1 {
		return errors.New("unexpected build snapshot projection")
	}
	*(dest[0].(*[]byte)) = r.raw
	return nil
}

// This exercises the real selected-row decoder, not SQL ownership or locks.
func TestBuildAttestationSelectedSnapshotDecoderPreservesExactJSONNumbers(t *testing.T) {
	at := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	b := domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: "recorded", Status: "passed", StartedAt: at, CreatedAt: at, SchemaVersion: domain.BuildRunSchemaVersion, SourceIdentity: map[string]any{"sequence": json.Number("9007199254740993"), "nested": map[string]any{"exact": json.Number("9223372036854775807")}}, Outputs: []domain.BuildOutput{{Digest: "sha256:recorded"}}}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ReadBuildAttestationBuild(t.Context(), buildAttestationDecodeQuery{raw}, b.TenantID, b.ID, false)
	if err != nil || v.ID != b.ID || v.TenantID != b.TenantID || v.ProjectID != b.ProjectID || v.ReleaseID != b.ReleaseID || !reflect.DeepEqual(v.SourceIdentity, b.SourceIdentity) || len(v.Outputs) != 1 || v.Outputs[0].Digest != b.Outputs[0].Digest || !v.CreatedAt.Equal(at) {
		t.Fatal("selected build decoder changed recorded source identity", err)
	}
}
func TestBuildAttestationSelectedSnapshotDecoderRejectsNullMalformedAndOversizedRows(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("null"), []byte("[]"), []byte("{"), make([]byte, (8<<20)+1)} {
		v, err := ReadBuildAttestationBuild(t.Context(), buildAttestationDecodeQuery{raw}, "tenant", "build", false)
		if !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(v, releasedomain.BuildRun{}) {
			t.Fatal("invalid selected build returned partial metadata", err)
		}
	}
}
