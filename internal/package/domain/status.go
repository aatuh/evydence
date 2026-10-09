package domain

import (
	"errors"
	"strings"
)

var ErrInvalidBundleState = errors.New("invalid release bundle state")

const (
	BundleStateGeneratedValue = "generated"
	BundleStatePublishedValue = "published"
	BundleStateRevokedValue   = "revoked"
)

type BundleState struct{ value string }

func ParseBundleState(value string) (BundleState, error) {
	value = strings.TrimSpace(value)
	switch value {
	case BundleStateGeneratedValue, BundleStatePublishedValue, BundleStateRevokedValue:
		return BundleState{value: value}, nil
	default:
		return BundleState{}, ErrInvalidBundleState
	}
}

func (state BundleState) String() string { return state.value }
func (state BundleState) IsZero() bool   { return state.value == "" }

func (state BundleState) CanTransitionTo(next BundleState) bool {
	switch state.String() {
	case BundleStateGeneratedValue:
		return next.String() == BundleStatePublishedValue || next.String() == BundleStateRevokedValue
	case BundleStatePublishedValue:
		return next.String() == BundleStateRevokedValue
	default:
		return false
	}
}
