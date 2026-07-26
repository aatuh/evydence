package app

import "errors"

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
