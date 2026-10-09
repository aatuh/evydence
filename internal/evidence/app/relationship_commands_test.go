package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestEvidenceRelationshipCommandsRequireFocusedDependencies(t *testing.T) {
	if command, err := NewRelationshipCommands(RelationshipCommandConfig{}); !errors.Is(err, ErrValidation) || command != nil {
		t.Fatal("empty relationship dependencies accepted", command, err)
	}
	f := newEvidenceServiceFixture(t)
	command, err := f.service.relationshipCommands()
	if err != nil || command == nil {
		t.Fatal("compatibility service did not compose focused relationships", err)
	}
}

func assertRelationshipPairAuthorization(t *testing.T, got []application.AuthorizationRequest, first, replacement application.ResourceReferences) {
	t.Helper()
	want := []application.AuthorizationRequest{
		{Scope: ScopeEvidenceWrite, ScopeOnly: true},
		{Scope: ScopeEvidenceWrite, Resources: first},
		{Scope: ScopeEvidenceWrite, Resources: replacement},
		{Scope: ScopeEvidenceWrite, Resources: first},
		{Scope: ScopeEvidenceWrite, Resources: replacement},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("initial and transactional authorization = %#v, want %#v", got, want)
	}
}

func TestEvidenceRelationshipsReauthorizeInsideTransactionAndRollbackOnDenial(t *testing.T) {
	for _, operation := range []string{"supersede", "link", "lifecycle"} {
		t.Run(operation, func(t *testing.T) {
			f := newEvidenceServiceFixture(t)
			item := f.mutableEvidence("original", "prod_1", testDigest('1'))
			replacement := f.mutableEvidence("replacement", "prod_2", testDigest('2'))
			for _, v := range []evidencedomain.EvidenceItem{item, replacement} {
				f.reader.evidence[v.ID], f.transactions.state.evidence[v.ID] = v, v
			}
			before := f.transactions.state.clone()
			f.transactions.beforeExecute = func() { f.authorizer.err = application.ErrForbidden }
			var err error
			switch operation {
			case "supersede":
				_, err = f.service.SupersedeEvidence(t.Context(), f.actor, item.ID, replacement.ID, "replace")
			case "link":
				_, err = f.service.LinkEvidence(t.Context(), f.actor, item.ID, "product", "prod_2")
			case "lifecycle":
				_, err = f.service.RecordLifecycleEvent(t.Context(), f.actor, item.ID, RecordLifecycleInput{Action: "amendment", Reason: "record", ReplacementID: replacement.ID})
			}
			if !errors.Is(err, application.ErrForbidden) || f.transactions.commits != 0 || f.transactions.rollbacks != 1 || !reflect.DeepEqual(before, f.transactions.state) {
				t.Fatalf("denied transaction published changes: err=%v state=%#v", err, f.transactions.state)
			}
		})
	}
}

func TestEvidenceRelationshipGuardsCheckCancellationBeforeInputWork(t *testing.T) {
	f := newEvidenceServiceFixture(t)
	c, err := f.service.relationshipCommands()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, err := range []error{
		c.AuthorizeSupersedeEvidence(ctx, f.actor, "", "", ""),
		c.AuthorizeLinkEvidence(ctx, f.actor, "", "", ""),
		c.AuthorizeLifecycleEvent(ctx, f.actor, "", RecordLifecycleInput{Details: map[string]any{"invalid": make(chan int)}}),
	} {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled guard performed input work: %v", err)
		}
	}
	if f.authorizer.calls != 0 || f.transactions.commits != 0 || f.transactions.rollbacks != 0 {
		t.Fatal("cancelled guard reached dependencies")
	}
}
