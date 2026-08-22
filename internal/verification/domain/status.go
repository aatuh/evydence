package domain

import (
	"errors"
	"strings"
)

var ErrInvalidVerificationState = errors.New("invalid verification state")

const SigningKeyStatusLegacyUnspecifiedValue = "legacy_unspecified"

type VerificationState struct{ value string }

func ParseVerificationState(value string) (VerificationState, error) {
	value = strings.TrimSpace(value)
	switch value {
	case VerificationStatePassed, VerificationStateFailed, VerificationStateNotVerified, VerificationStateLimited, VerificationStateSkipped, VerificationStateError:
		return VerificationState{value: value}, nil
	default:
		return VerificationState{}, ErrInvalidVerificationState
	}
}

func (state VerificationState) String() string { return state.value }
func (state VerificationState) IsZero() bool   { return state.value == "" }

type SigningKeyStatus struct{ value string }

func ParseSigningKeyStatus(value string) (SigningKeyStatus, error) {
	value = strings.TrimSpace(value)
	switch value {
	case SigningKeyStatusActive, SigningKeyStatusRetiring, SigningKeyStatusRevoked, SigningKeyStatusLegacyUnspecifiedValue:
		return SigningKeyStatus{value: value}, nil
	default:
		return SigningKeyStatus{}, ErrInvalidVerificationState
	}
}

func (status SigningKeyStatus) String() string { return status.value }
func (status SigningKeyStatus) IsZero() bool   { return status.value == "" }
