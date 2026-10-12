package wiring

import (
	"context"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

type evidencePointReaderStub struct{}

func (evidencePointReaderStub) GetEvidencePoint(context.Context, string, string, evidencequery.EvidenceReadGuard) (evidencequery.EvidencePoint, error) {
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

type lifecyclePageReaderStub struct{}

func (lifecyclePageReaderStub) PageLifecycleEvents(context.Context, string, string, appquery.PageRequest, *appquery.SortKey, evidencequery.EvidenceReadGuard) (evidencequery.LifecyclePage, error) {
	return evidencequery.LifecyclePage{}, nil
}

func TestBuildLifecycleEventsQueryRequiresReader(t *testing.T) {
	if _, err := BuildLifecycleEventsQuery(nil); err == nil {
		t.Fatal("lifecycle query accepted a missing database reader")
	}
	query, err := BuildLifecycleEventsQuery(lifecyclePageReaderStub{})
	if err != nil || query == nil {
		t.Fatalf("compose lifecycle query=%T error=%v", query, err)
	}
}
