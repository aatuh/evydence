package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func TestMemoryEvidencePointUsesCurrentCompleteDetachedMetadata(t *testing.T) {
	tx, _, _, actor := memoryLifecycleFixture(t)
	reader, ok := tx.Repositories().Evidence.(evidencequery.EvidencePointReader)
	if !ok {
		t.Fatal("memory Evidence repository lacks native evidence point reads")
	}
	query, err := evidencequery.NewEvidencePoints(reader)
	if err != nil {
		t.Fatal(err)
	}
	e := tx.state.Evidence["tenant-evidence"]
	e.Subtype, e.Title, e.SourceSystem = "review", "Recorded evidence", "fixture"
	e.SourceIdentity = map[string]any{"nested": map[string]any{"number": json.Number("9007199254740993")}}
	e.Metadata = map[string]any{"nested": map[string]any{"value": "original"}}
	e.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: "opaque"}}
	e.RelatedEvidenceRefs = []domain.EvidenceRef{{Type: "evidence_item", ID: "related", Relationship: "supports"}}
	e.Supersedes, e.SupersededBy = "older", "newer"
	e.SignatureRefs, e.Tags, e.Limitations = []string{"signature"}, []string{"reviewed"}, []string{"fixture"}
	e.Warnings = []domain.EvidenceNotice{{Code: "NOTICE", Message: "Recorded limitation"}}
	tx.state.Evidence[e.ID] = e
	want, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	item, err := query.GetEvidence(t.Context(), actor, " tenant-evidence ")
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(domain.EvidenceFromContextModel(item))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("point query lost recorded public fields or exact numbers", string(got), string(want), err)
	}
	item.Metadata["nested"].(map[string]any)["value"] = "changed"
	item.SourceIdentity["nested"].(map[string]any)["number"] = "changed"
	item.Tags[0], item.SubjectRefs[0].ID, item.RelatedEvidenceRefs[0].ID = "changed", "changed", "changed"
	current, err := json.Marshal(tx.state.Evidence[e.ID])
	if err != nil || !bytes.Equal(current, want) {
		t.Fatal("point reads or caller mutation changed current rows", err)
	}
	actor.ResourceGrants = nil
	if _, err := query.GetEvidence(t.Context(), actor, e.ID); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("point query retained revoked grants", err)
	}
	guard := func(application.ResourceReferences) error { return nil }
	for _, id := range []string{"bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		if _, err := reader.GetEvidencePoint(t.Context(), "tenant", id, guard); !errors.Is(err, evidencequery.ErrValidation) {
			t.Fatal("malformed evidence point identifier accepted", err)
		}
	}
	for _, args := range [][2]string{{"foreign", e.ID}, {"tenant", "missing"}} {
		if point, err := reader.GetEvidencePoint(t.Context(), args[0], args[1], guard); !errors.Is(err, evidencequery.ErrNotFound) || !reflect.DeepEqual(point, evidencequery.EvidencePoint{}) {
			t.Fatal("foreign or missing point exposed metadata", point, err)
		}
	}
	base, cancel := context.WithCancel(t.Context())
	point, err := reader.GetEvidencePoint(base, "tenant", e.ID, func(application.ResourceReferences) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(point, evidencequery.EvidencePoint{}) {
		t.Fatal("point cancellation returned partial data", point, err)
	}
	if _, err := reader.GetEvidencePoint(t.Context(), "tenant", e.ID, guard); err != nil {
		t.Fatal("canceled point read retained a transaction lock", err)
	}
}
