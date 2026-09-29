package wiring

import (
	"context"
	"testing"

	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

type evidencePointReaderStub struct{}

func (evidencePointReaderStub) GetEvidencePoint(context.Context, string, string) (evidencequery.EvidencePoint, error) {
	return evidencequery.EvidencePoint{}, nil
}

func TestBuildEvidencePointQueryRequiresReader(t *testing.T) {
	if _, err := BuildEvidencePointQuery(nil); err == nil {
		t.Fatal("query service accepted a missing database reader")
	}
	query, err := BuildEvidencePointQuery(evidencePointReaderStub{})
	if err != nil || query == nil {
		t.Fatalf("compose evidence point query=%T error=%v", query, err)
	}
}
