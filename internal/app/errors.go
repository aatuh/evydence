package app

import (
	"errors"
	"fmt"
)

var (
	ErrValidation                  = errors.New("validation failed")
	ErrUnauthorized                = errors.New("unauthorized")
	ErrForbidden                   = errors.New("forbidden")
	ErrNotFound                    = errors.New("not found")
	ErrConflict                    = errors.New("conflict")
	ErrImmutable                   = errors.New("immutable resource")
	ErrIdempotencyConflict         = errors.New("idempotency key reused with different request")
	ErrIdempotencyInProgress       = errors.New("idempotency request is in progress")
	ErrIdempotencyFailed           = errors.New("idempotency request previously failed")
	ErrVerificationFailed          = errors.New("verification failed")
	ErrFullVerificationUnavailable = errors.New("full cosign verification is unavailable because no verifier or trust policy is configured")
	ErrRateLimited                 = errors.New("rate limited")
)

// VersionConflictError reports a safe, tenant-authorized revision number when
// a conditional transition lost a race. It deliberately carries no resource
// data, actor data, or prior request content.
type VersionConflictError struct {
	CurrentRevision int64
}

func (e VersionConflictError) Error() string {
	return fmt.Sprintf("resource revision conflict (current revision %d)", e.CurrentRevision)
}

func (VersionConflictError) Unwrap() error { return ErrConflict }

// NewVersionConflict constructs the conflict only for a valid persisted
// revision. Callers without a safe current revision must return ErrConflict.
func NewVersionConflict(currentRevision int64) error {
	if currentRevision < 1 {
		return ErrConflict
	}
	return VersionConflictError{CurrentRevision: currentRevision}
}

// CurrentRevision returns the safe revision metadata carried by a conditional
// write conflict. It intentionally ignores ordinary state conflicts.
func CurrentRevision(err error) (int64, bool) {
	var conflict VersionConflictError
	if !errors.As(err, &conflict) || conflict.CurrentRevision < 1 {
		return 0, false
	}
	return conflict.CurrentRevision, true
}
