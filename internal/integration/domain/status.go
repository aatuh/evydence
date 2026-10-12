package domain

import (
	"errors"
	"strings"
)

var ErrInvalidCollectorStatus = errors.New("invalid collector status")

const (
	CollectorStatusActiveValue   = "active"
	CollectorStatusDisabledValue = "disabled"
	CollectorStatusRevokedValue  = "revoked"
)

type CollectorStatus struct{ value string }

func ParseCollectorStatus(value string) (CollectorStatus, error) {
	value = strings.TrimSpace(value)
	switch value {
	case CollectorStatusActiveValue, CollectorStatusDisabledValue, CollectorStatusRevokedValue:
		return CollectorStatus{value: value}, nil
	default:
		return CollectorStatus{}, ErrInvalidCollectorStatus
	}
}

func (status CollectorStatus) String() string { return status.value }
func (status CollectorStatus) IsZero() bool   { return status.value == "" }
