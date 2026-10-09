package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

func TestLedgerEvidencePayloadParserProbesLateVulnerabilityScanReleaseScope(t *testing.T) {
	raw := []byte(`{"scanner":"generic","findings":[{"vulnerability":"CVE-2026-0001","severity":"high"}],"target_ref":"pkg:oci/api","release_id":" rel_late "}`)

	scope, err := (ledgerEvidencePayloadParser{}).ProbeVulnerabilityScanScope(context.Background(), evidenceapp.BytesPayloadSource(raw))
	if err != nil {
		t.Fatalf("ProbeVulnerabilityScanScope: %v", err)
	}
	if scope.ReleaseID != "rel_late" {
		t.Fatalf("release scope = %#v", scope)
	}
}

func TestLedgerEvidencePayloadParserProbeVerifiesDigestBoundSource(t *testing.T) {
	source := evidenceapp.BytesPayloadSource([]byte(`{"release_id":"rel_1","findings":[]}`))
	source.Digest = "sha256:" + strings.Repeat("0", 64)

	_, err := (ledgerEvidencePayloadParser{}).ProbeVulnerabilityScanScope(context.Background(), source)
	if !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatalf("ProbeVulnerabilityScanScope error = %v, want validation", err)
	}
}

func TestLedgerVulnerabilityScanProductionWiringRejectsMissingReleaseBeforeFullNormalization(t *testing.T) {
	ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	actor, _, _ := setupReleaseRiskFixture(t, ledger)
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_missing","findings":"full-parser-would-reject"}`)

	if _, err := ledger.UploadVulnerabilityScan(context.Background(), actor, raw); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UploadVulnerabilityScan error = %v, want not found before full parser validation", err)
	}
	if len(ledger.scans) != 0 {
		t.Fatalf("denied scan was persisted: %#v", ledger.scans)
	}
}

func TestLedgerVulnerabilityScanProductionWiringRejectsSequentialPayloadDrift(t *testing.T) {
	for _, changeAt := range []int{2, 3} {
		t.Run("change on open "+strconv.Itoa(changeAt), func(t *testing.T) {
			ledger := newLegacyLedgerFixture(Config{APIKeyPepper: "test-pepper", Now: fixedNow, ObjectStore: newTestObjectStore()})
			actor, release, _ := setupReleaseRiskFixture(t, ledger)
			raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"` + release.ID + `","findings":[]}`)
			driftedReleaseID := strings.Repeat("x", len(release.ID))
			drifted := []byte(strings.Replace(string(raw), release.ID, driftedReleaseID, 1))
			if len(drifted) != len(raw) {
				t.Fatal("test payload sizes differ")
			}
			opens := 0
			source := PayloadSource{
				Digest: hashBytes(raw), Size: int64(len(raw)),
				Open: func() (io.ReadCloser, error) {
					opens++
					body := raw
					if opens >= changeAt {
						body = drifted
					}
					return io.NopCloser(bytes.NewReader(body)), nil
				},
			}

			if _, err := ledger.UploadVulnerabilityScanPayload(context.Background(), actor, source); !errors.Is(err, ErrValidation) {
				t.Fatalf("UploadVulnerabilityScanPayload error = %v, want validation", err)
			}
			if opens != changeAt || len(ledger.scans) != 0 {
				t.Fatalf("payload drift progression: opens=%d scans=%d", opens, len(ledger.scans))
			}
		})
	}
}
