package domain

import (
	"errors"
	"strings"
)

var ErrInvalidIncidentStatus = errors.New("invalid incident status")

const (
	IncidentStatusOpenValue      = "open"
	IncidentStatusContainedValue = "contained"
	IncidentStatusResolvedValue  = "resolved"
	IncidentStatusClosedValue    = "closed"
)

type IncidentStatus struct{ value string }

func ParseIncidentStatus(value string) (IncidentStatus, error) {
	value = strings.TrimSpace(value)
	switch value {
	case IncidentStatusOpenValue, IncidentStatusContainedValue, IncidentStatusResolvedValue, IncidentStatusClosedValue:
		return IncidentStatus{value: value}, nil
	default:
		return IncidentStatus{}, ErrInvalidIncidentStatus
	}
}

func (status IncidentStatus) String() string { return status.value }
func (status IncidentStatus) IsZero() bool   { return status.value == "" }
