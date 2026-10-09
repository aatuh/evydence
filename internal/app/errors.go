package app

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	ErrRetryableSigning            = errors.New("signing provider temporarily unavailable")
	ErrFullVerificationUnavailable = errors.New("full cosign verification is unavailable because no verifier or trust policy is configured")
	ErrRateLimited                 = errors.New("rate limited")
	ErrDependencyUnavailable       = errors.New("dependency temporarily unavailable")
)

// ErrorCode is the stable, SDK-switchable code returned in RFC 9457 Problem
// Details. Values are defined in the embedded error catalog rather than being
// inferred from implementation-specific Go error strings.
type ErrorCode string

const (
	CodeValidationFailed                  ErrorCode = "VALIDATION_FAILED"
	CodeUnauthorized                      ErrorCode = "UNAUTHORIZED"
	CodeForbidden                         ErrorCode = "FORBIDDEN"
	CodeNotFound                          ErrorCode = "NOT_FOUND"
	CodeVersionConflict                   ErrorCode = "VERSION_CONFLICT"
	CodeConflict                          ErrorCode = "CONFLICT"
	CodeEvidenceImmutable                 ErrorCode = "EVIDENCE_IMMUTABLE"
	CodeIdempotencyKeyReused              ErrorCode = "IDEMPOTENCY_KEY_REUSED"
	CodeIdempotencyInProgress             ErrorCode = "IDEMPOTENCY_IN_PROGRESS"
	CodeIdempotencyRequestFailed          ErrorCode = "IDEMPOTENCY_REQUEST_FAILED"
	CodeCosignFullVerificationUnavailable ErrorCode = "COSIGN_FULL_VERIFICATION_UNAVAILABLE"
	CodeVerificationFailed                ErrorCode = "VERIFICATION_FAILED"
	CodeRateLimited                       ErrorCode = "RATE_LIMITED"
	CodeSigningProviderUnavailable        ErrorCode = "SIGNING_PROVIDER_UNAVAILABLE"
	CodeDependencyUnavailable             ErrorCode = "DEPENDENCY_UNAVAILABLE"
	CodeInternalError                     ErrorCode = "INTERNAL_ERROR"
)

// RetryClass is a stable client action classification. It is independent of
// HTTP status, so clients do not need to infer whether a retry is sensible
// from a message or transport failure alone.
type RetryClass string

const (
	RetryClassNone                  RetryClass = "none"
	RetryClassRefreshAndRetry       RetryClass = "refresh_and_retry"
	RetryClassIdempotencyInProgress RetryClass = "idempotency_in_progress"
	RetryClassRateLimited           RetryClass = "rate_limited"
	RetryClassTransientProvider     RetryClass = "transient_provider"
	RetryClassDependencyUnavailable RetryClass = "dependency_unavailable"
)

// FieldViolation identifies a safe, client-supplied JSON Pointer field path
// and machine-readable validation reason. It intentionally has no raw parser
// or provider message field.
type FieldViolation struct {
	Field string `json:"field"`
	Code  string `json:"code"`
}

// ErrorDefinition is a public, generated-catalog entry. Detail is a fixed,
// reviewed safe string and must never be replaced with an underlying cause.
type ErrorDefinition struct {
	Code              ErrorCode  `json:"code"`
	Status            int        `json:"status"`
	Detail            string     `json:"detail"`
	Retryable         bool       `json:"retryable"`
	RetryClass        RetryClass `json:"retry_class"`
	RetryAfterSeconds int        `json:"retry_after_seconds,omitempty"`
}

// ProblemDetails is the transport-neutral projection of an application error.
// The HTTP adapter adds RFC 9457 fields, request ID, and instance path.
type ProblemDetails struct {
	ErrorDefinition
	Violations []FieldViolation `json:"violations,omitempty"`
}

// ValidationError carries only normalized field violations while retaining
// ErrValidation for existing application callers and errors.Is checks.
type ValidationError struct {
	violations []FieldViolation
}

func (e *ValidationError) Error() string { return ErrValidation.Error() }

func (*ValidationError) Unwrap() error { return ErrValidation }

// NewValidationError creates an error whose client-visible field paths and
// codes have been strictly normalized. Unsafe or malformed paths are omitted.
func NewValidationError(violations ...FieldViolation) error {
	return &ValidationError{violations: safeFieldViolations(violations)}
}

//go:embed error_catalog.json
var errorCatalogJSON []byte

var (
	errorCatalogEntries = mustErrorCatalog(errorCatalogJSON)
	errorCatalogByCode  = indexErrorCatalog(errorCatalogEntries)
)

func mustErrorCatalog(raw []byte) []ErrorDefinition {
	var entries []ErrorDefinition
	if err := json.Unmarshal(raw, &entries); err != nil {
		panic(fmt.Sprintf("invalid embedded error catalog: %v", err))
	}
	if len(entries) == 0 {
		panic("embedded error catalog is empty")
	}
	return entries
}

func indexErrorCatalog(entries []ErrorDefinition) map[ErrorCode]ErrorDefinition {
	byCode := make(map[ErrorCode]ErrorDefinition, len(entries))
	for _, entry := range entries {
		if entry.Code == "" || entry.Status < 400 || entry.Status > 599 || strings.TrimSpace(entry.Detail) == "" || entry.RetryClass == "" {
			panic(fmt.Sprintf("invalid embedded error catalog entry: %#v", entry))
		}
		if _, duplicate := byCode[entry.Code]; duplicate {
			panic(fmt.Sprintf("duplicate embedded error catalog code: %s", entry.Code))
		}
		byCode[entry.Code] = entry
	}
	if _, ok := byCode[CodeInternalError]; !ok {
		panic("embedded error catalog is missing INTERNAL_ERROR")
	}
	return byCode
}

// ErrorCatalog returns a copy of the complete public error contract for
// generators and in-process consumers. Callers cannot mutate the catalog.
func ErrorCatalog() []ErrorDefinition {
	return append([]ErrorDefinition(nil), errorCatalogEntries...)
}

// DescribeProblem maps sentinels and wrapped causes to one safe catalog entry.
// It never exposes a cause message, database detail, token, URL, or parser
// output to a transport adapter.
func DescribeProblem(err error) ProblemDetails {
	definition := errorCatalogByCode[classifyProblem(err)]
	details := ProblemDetails{ErrorDefinition: definition}
	var validation *ValidationError
	if errors.As(err, &validation) {
		details.Violations = append([]FieldViolation(nil), validation.violations...)
	}
	return details
}

func classifyProblem(err error) ErrorCode {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return CodeUnauthorized
	case errors.Is(err, ErrForbidden):
		return CodeForbidden
	case errors.Is(err, ErrNotFound):
		return CodeNotFound
	case CurrentVersionConflict(err):
		return CodeVersionConflict
	case errors.Is(err, ErrImmutable):
		return CodeEvidenceImmutable
	case errors.Is(err, ErrIdempotencyConflict):
		return CodeIdempotencyKeyReused
	case errors.Is(err, ErrIdempotencyInProgress):
		return CodeIdempotencyInProgress
	case errors.Is(err, ErrIdempotencyFailed):
		return CodeIdempotencyRequestFailed
	case errors.Is(err, ErrConflict):
		return CodeConflict
	case errors.Is(err, ErrFullVerificationUnavailable):
		return CodeCosignFullVerificationUnavailable
	case errors.Is(err, ErrVerificationFailed):
		return CodeVerificationFailed
	case errors.Is(err, ErrRateLimited):
		return CodeRateLimited
	case errors.Is(err, ErrRetryableSigning):
		return CodeSigningProviderUnavailable
	case errors.Is(err, ErrDependencyUnavailable):
		return CodeDependencyUnavailable
	case errors.Is(err, ErrValidation):
		return CodeValidationFailed
	default:
		return CodeInternalError
	}
}

func safeFieldViolations(violations []FieldViolation) []FieldViolation {
	const maxViolations = 32
	result := make([]FieldViolation, 0, len(violations))
	for _, violation := range violations {
		if len(result) == maxViolations {
			break
		}
		field, code := strings.TrimSpace(violation.Field), strings.TrimSpace(violation.Code)
		if !safeJSONPointer(field) || !safeViolationCode(code) {
			continue
		}
		result = append(result, FieldViolation{Field: field, Code: code})
	}
	return result
}

func safeJSONPointer(value string) bool {
	if len(value) < 2 || len(value) > 256 || value[0] != '/' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character == '~' {
			if index+1 >= len(value) || (value[index+1] != '0' && value[index+1] != '1') {
				return false
			}
			index++
			continue
		}
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '/' || character == '_' || character == '-' || character == '.' || character == '~' {
			continue
		}
		return false
	}
	return true
}

func safeViolationCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

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
