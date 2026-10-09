package domain

import (
	"errors"
	"strings"
	"time"
)

var ErrInvalidState = errors.New("invalid release state")

const (
	ReleaseStateDraftValue    = "draft"
	ReleaseStateFrozenValue   = "frozen"
	ReleaseStateApprovedValue = "approved"

	ReleaseCandidateStateOpenValue     = "open"
	ReleaseCandidateStatePromotedValue = "promoted"
	ReleaseCandidateStateRejectedValue = "rejected"
)

type ReleaseState struct{ value string }

func ParseReleaseState(value string) (ReleaseState, error) {
	value = strings.TrimSpace(value)
	switch value {
	case ReleaseStateDraftValue, ReleaseStateFrozenValue, ReleaseStateApprovedValue:
		return ReleaseState{value: value}, nil
	default:
		return ReleaseState{}, ErrInvalidState
	}
}

func (state ReleaseState) String() string { return state.value }
func (state ReleaseState) IsZero() bool   { return state.value == "" }

type ReleaseCandidateState struct{ value string }

func ParseReleaseCandidateState(value string) (ReleaseCandidateState, error) {
	value = strings.TrimSpace(value)
	switch value {
	case ReleaseCandidateStateOpenValue, ReleaseCandidateStatePromotedValue, ReleaseCandidateStateRejectedValue:
		return ReleaseCandidateState{value: value}, nil
	default:
		return ReleaseCandidateState{}, ErrInvalidState
	}
}

func (state ReleaseCandidateState) String() string { return state.value }
func (state ReleaseCandidateState) IsZero() bool   { return state.value == "" }

func NewRelease(id, tenantID, productID, version string, createdAt time.Time) (Release, error) {
	id = strings.TrimSpace(id)
	tenantID = strings.TrimSpace(tenantID)
	productID = strings.TrimSpace(productID)
	version = strings.TrimSpace(version)
	if id == "" || tenantID == "" || productID == "" || version == "" || createdAt.IsZero() {
		return Release{}, ErrInvalidState
	}
	state, _ := ParseReleaseState(ReleaseStateDraftValue)
	return Release{ID: id, TenantID: tenantID, ProductID: productID, Version: version, Revision: 1, State: state, CreatedAt: createdAt.UTC()}, nil
}

func (release Release) Freeze(at time.Time) (Release, error) {
	if release.State.String() != ReleaseStateDraftValue || at.IsZero() {
		return Release{}, ErrInvalidState
	}
	state, _ := ParseReleaseState(ReleaseStateFrozenValue)
	release.State = state
	release.Revision++
	frozenAt := at.UTC()
	release.FrozenAt = &frozenAt
	return release, nil
}

func (release Release) Approve(at time.Time) (Release, error) {
	if release.State.String() != ReleaseStateFrozenValue || at.IsZero() {
		return Release{}, ErrInvalidState
	}
	state, _ := ParseReleaseState(ReleaseStateApprovedValue)
	release.State = state
	release.Revision++
	approvedAt := at.UTC()
	release.ApprovedAt = &approvedAt
	return release, nil
}
