package domain

import (
	"testing"
	"time"
)

func TestReleaseStatesAndTransitions(t *testing.T) {
	for _, value := range []string{ReleaseStateDraftValue, ReleaseStateFrozenValue, ReleaseStateApprovedValue} {
		state, err := ParseReleaseState(" " + value + " ")
		if err != nil || state.String() != value || state.IsZero() {
			t.Fatalf("ParseReleaseState(%q)=(%q, %v)", value, state.String(), err)
		}
	}
	if _, err := ParseReleaseState("unknown"); err == nil {
		t.Fatal("unknown release state was accepted")
	}
	if !(ReleaseState{}).IsZero() {
		t.Fatal("zero release state was not reported")
	}
	for _, value := range []string{ReleaseCandidateStateOpenValue, ReleaseCandidateStatePromotedValue, ReleaseCandidateStateRejectedValue} {
		state, err := ParseReleaseCandidateState(value)
		if err != nil || state.String() != value || state.IsZero() {
			t.Fatalf("ParseReleaseCandidateState(%q)=(%q, %v)", value, state.String(), err)
		}
	}
	if _, err := ParseReleaseCandidateState("unknown"); err == nil {
		t.Fatal("unknown candidate state was accepted")
	}
	if !(ReleaseCandidateState{}).IsZero() {
		t.Fatal("zero candidate state was not reported")
	}

	now := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.FixedZone("test", 2*60*60))
	release, err := NewRelease(" rel_1 ", " ten_1 ", " prod_1 ", " 1.0.0 ", now)
	if err != nil || release.State.String() != ReleaseStateDraftValue || release.CreatedAt.Location() != time.UTC {
		t.Fatalf("NewRelease()=(%#v, %v)", release, err)
	}
	if _, err := NewRelease("", "ten_1", "prod_1", "1.0.0", now); err == nil {
		t.Fatal("release with missing identity was accepted")
	}
	if _, err := release.Approve(now); err == nil {
		t.Fatal("draft release skipped freeze")
	}
	frozen, err := release.Freeze(now.Add(time.Minute))
	if err != nil || frozen.State.String() != ReleaseStateFrozenValue || frozen.Revision != 2 || frozen.FrozenAt == nil {
		t.Fatalf("Freeze()=(%#v, %v)", frozen, err)
	}
	if _, err := frozen.Freeze(time.Time{}); err == nil {
		t.Fatal("frozen release was frozen again")
	}
	approved, err := frozen.Approve(now.Add(2 * time.Minute))
	if err != nil || approved.State.String() != ReleaseStateApprovedValue || approved.Revision != 3 || approved.ApprovedAt == nil {
		t.Fatalf("Approve()=(%#v, %v)", approved, err)
	}
}
