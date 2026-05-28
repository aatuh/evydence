package app

import "errors"

var (
	ErrValidation          = errors.New("validation failed")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrForbidden           = errors.New("forbidden")
	ErrNotFound            = errors.New("not found")
	ErrConflict            = errors.New("conflict")
	ErrImmutable           = errors.New("immutable resource")
	ErrIdempotencyConflict = errors.New("idempotency key reused with different request")
	ErrVerificationFailed  = errors.New("verification failed")
	ErrRateLimited         = errors.New("rate limited")
)
