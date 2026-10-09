package domain

import (
	"errors"
	"strings"
)

var ErrInvalidDecisionStatus = errors.New("invalid vulnerability decision status")

const (
	DecisionStatusAffectedValue           = "affected"
	DecisionStatusNotAffectedValue        = "not_affected"
	DecisionStatusFixedValue              = "fixed"
	DecisionStatusUnderInvestigationValue = "under_investigation"
)

type DecisionStatus struct{ value string }

func ParseDecisionStatus(value string) (DecisionStatus, error) {
	value = strings.TrimSpace(value)
	switch value {
	case DecisionStatusAffectedValue, DecisionStatusNotAffectedValue, DecisionStatusFixedValue, DecisionStatusUnderInvestigationValue:
		return DecisionStatus{value: value}, nil
	default:
		return DecisionStatus{}, ErrInvalidDecisionStatus
	}
}

func (status DecisionStatus) String() string { return status.value }
func (status DecisionStatus) IsZero() bool   { return status.value == "" }

func (status DecisionStatus) CanTransitionTo(next DecisionStatus) bool {
	return !status.IsZero() && !next.IsZero()
}
