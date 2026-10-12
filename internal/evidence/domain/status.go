package domain

import (
	"errors"
	"strings"
)

var ErrInvalidLifecycleState = errors.New("invalid evidence lifecycle state")

const (
	EvidenceLifecycleAcceptedValue        = "accepted"
	EvidenceLifecycleAmendmentValue       = "amendment"
	EvidenceLifecycleRedactionValue       = "redaction"
	EvidenceLifecycleTombstoneValue       = "tombstone"
	EvidenceLifecycleRetentionMarkerValue = "retention_marker"
)

type EvidenceLifecycleState struct{ value string }

func ParseEvidenceLifecycleState(value string) (EvidenceLifecycleState, error) {
	value = strings.TrimSpace(value)
	switch value {
	case EvidenceLifecycleAcceptedValue, EvidenceLifecycleAmendmentValue, EvidenceLifecycleRedactionValue, EvidenceLifecycleTombstoneValue, EvidenceLifecycleRetentionMarkerValue:
		return EvidenceLifecycleState{value: value}, nil
	default:
		return EvidenceLifecycleState{}, ErrInvalidLifecycleState
	}
}

func (state EvidenceLifecycleState) String() string { return state.value }
func (state EvidenceLifecycleState) IsZero() bool   { return state.value == "" }

func NewSubjectReference(subjectType, subjectID, digest string) (SubjectRef, error) {
	subjectType = strings.TrimSpace(subjectType)
	subjectID = strings.TrimSpace(subjectID)
	digest = strings.TrimSpace(digest)
	if subjectType == "" || subjectID == "" {
		return SubjectRef{}, ErrInvalidLifecycleState
	}
	return SubjectRef{Type: subjectType, ID: subjectID, Digest: digest}, nil
}
