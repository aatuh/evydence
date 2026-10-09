package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestGenericEvidenceCreationRejectsRawBudgetsBeforeEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*CreateEvidenceInput)
	}{
		{"parent", func(in *CreateEvidenceInput) { in.ProductID = strings.Repeat(" ", 1025) + "product" }},
		{"title", func(in *CreateEvidenceInput) { in.Title = strings.Repeat(" ", 65537) + "Evidence" }},
		{"title-nul", func(in *CreateEvidenceInput) { in.Title = "bad\x00title" }},
		{"metadata-nul", func(in *CreateEvidenceInput) {
			in.Metadata = map[string]any{"nested": map[string]any{"note": "bad\x00value"}}
		}},
		{"subject-count", func(in *CreateEvidenceInput) {
			in.SubjectRefs = make([]evidencedomain.SubjectRef, 1025)
			for n := range in.SubjectRefs {
				in.SubjectRefs[n] = evidencedomain.SubjectRef{Type: "opaque", ID: "label"}
			}
		}},
		{"tag-count", func(in *CreateEvidenceInput) { in.Tags = make([]string, 1025) }},
		{"utc-time", func(in *CreateEvidenceInput) {
			in.ObservedAt = time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("offset", 3600))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newEvidenceServiceFixture(t)
			c, err := NewEvidenceCreationCommands(creationConfig(f))
			if err != nil {
				t.Fatal(err)
			}
			in := CreateEvidenceInput{Type: "manual", Title: "Evidence", PayloadHash: testDigest('a')}
			tc.change(&in)
			v, err := c.CreateEvidence(t.Context(), f.actor, in)
			if !errors.Is(err, ErrValidation) || v.ID != "" || f.transactions.commits != 0 || len(f.transactions.state.evidence) != 0 || len(f.transactions.state.audit) != 0 {
				t.Fatalf("invalid evidence input reached effects: id=%q err=%v commits=%d evidence=%d audits=%d", v.ID, err, f.transactions.commits, len(f.transactions.state.evidence), len(f.transactions.state.audit))
			}
		})
	}
}
