package httpapi

import (
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestManualDecisionFixtureUsesCurrentRepositoryAndNoAggregateClock(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory})
	owner := seedRiskQueryFixtureScope(t, ledger, "Owner")
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("manual decision consulted aggregate clock") }})
	commands := riskCommandFixture{catalogFixtureCommands{ledger: rebound}}
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	input := riskapp.CreateVulnerabilityDecisionInput{Status: "fixed", Justification: "reviewed", ImpactStatement: "patched", ActionStatement: "ship", CustomerVisible: true, InternalNotes: "private new triage"}
	v, err := commands.CreateVulnerabilityDecision(t.Context(), owner.actor, owner.head.FindingID, input)
	if err != nil || v.ID == "" || v.Supersedes != owner.head.ID || v.ReleaseID != owner.release.ID || v.Status.String() != "fixed" || v.InternalNotes != input.InternalNotes {
		t.Fatal("native manual fixture lost current ownership or decision content", err)
	}
	after, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	old := before.Decisions[owner.head.ID]
	old.SupersededBy = v.ID
	if !reflect.DeepEqual(after.Decisions[old.ID], old) || len(after.Decisions) != len(before.Decisions)+1 {
		t.Fatal("native manual command rewrote historical core or lost its append")
	}
	audits := 0
	for _, e := range after.AuditEntries[owner.actor.TenantID] {
		if e.EntryType == "vulnerability_decision.superseded" && e.SubjectID == owner.head.ID || e.EntryType == "vulnerability_decision.created" && e.SubjectID == owner.head.FindingID && e.OccurredAt.Equal(v.CreatedAt) {
			audits++
		}
	}
	oldAudits := 0
	for _, e := range before.AuditEntries[owner.actor.TenantID] {
		if e.EntryType == "vulnerability_decision.superseded" && e.SubjectID == owner.head.ID {
			oldAudits++
		}
	}
	if audits-oldAudits != 2 {
		t.Fatal("native manual append did not commit both expected audit effects")
	}
	factory.fail = true
	v, err = commands.CreateVulnerabilityDecision(t.Context(), owner.actor, owner.head.FindingID, input)
	if err == nil || !reflect.DeepEqual(v, riskdomain.VulnerabilityDecision{}) {
		t.Fatal("failed manual commit returned partial decision", err)
	}
	factory.fail = false
	failed, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(after, failed) {
		t.Fatal("failed native manual command published decision, supersession or audit", err)
	}
}
