package app

import (
	"errors"
	"fmt"
	"testing"
)

func TestDescribeProblemUsesCatalogSafeDetailsAndPreservesCause(t *testing.T) {
	providerCause := errors.New("https://provider.example.invalid/sign?token=super-secret failed")
	err := fmt.Errorf("signing request failed: %w", fmt.Errorf("%w: %w", ErrRetryableSigning, providerCause))
	details := DescribeProblem(err)

	if details.Code != CodeSigningProviderUnavailable || details.Status != 503 {
		t.Fatalf("details = %#v, want signing provider unavailable 503", details)
	}
	if !details.Retryable || details.RetryClass != RetryClassTransientProvider || details.RetryAfterSeconds < 1 {
		t.Fatalf("retry metadata = %#v, want transient retry guidance", details)
	}
	if details.Detail == "" || containsSensitiveProblemText(details.Detail) {
		t.Fatalf("unsafe problem detail = %q", details.Detail)
	}
	if !errors.Is(err, providerCause) || !errors.Is(err, ErrRetryableSigning) {
		t.Fatalf("wrapped causes were not preserved: %v", err)
	}
}

func TestValidationProblemCarriesOnlySafeFieldViolations(t *testing.T) {
	err := NewValidationError(
		FieldViolation{Field: "/name", Code: "required"},
		FieldViolation{Field: "/credentials/token", Code: "invalid_format"},
		FieldViolation{Field: "/a~0b~1c", Code: "escaped_pointer"},
		FieldViolation{Field: "not-a-json-pointer", Code: "invalid"},
		FieldViolation{Field: "/bad~escape", Code: "invalid"},
		FieldViolation{Field: "/another~2escape", Code: "invalid"},
	)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("validation error does not wrap ErrValidation: %v", err)
	}
	details := DescribeProblem(err)
	if details.Code != CodeValidationFailed || details.Status != 400 {
		t.Fatalf("validation details = %#v", details)
	}
	if len(details.Violations) != 3 || details.Violations[0].Field != "/name" || details.Violations[1].Field != "/credentials/token" || details.Violations[2].Field != "/a~0b~1c" {
		t.Fatalf("safe validation violations = %#v", details.Violations)
	}
	for _, violation := range details.Violations {
		if violation.Code == "" {
			t.Fatalf("violation exposes unsafe or incomplete content: %#v", violation)
		}
	}
}

func TestErrorCatalogIsCompleteAndStable(t *testing.T) {
	seen := map[ErrorCode]struct{}{}
	for _, definition := range ErrorCatalog() {
		if definition.Code == "" || definition.Status < 400 || definition.Status > 599 || definition.Detail == "" || definition.RetryClass == "" {
			t.Fatalf("invalid error catalog definition: %#v", definition)
		}
		if _, duplicate := seen[definition.Code]; duplicate {
			t.Fatalf("duplicate error catalog code %q", definition.Code)
		}
		seen[definition.Code] = struct{}{}
	}
	for _, code := range []ErrorCode{CodeValidationFailed, CodeRateLimited, CodeSigningProviderUnavailable, CodeInternalError} {
		if _, ok := seen[code]; !ok {
			t.Fatalf("required catalog code %q is missing", code)
		}
	}
}

func TestDescribeProblemMapsEveryDocumentedErrorClass(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code ErrorCode
	}{
		{"validation", ErrValidation, CodeValidationFailed},
		{"unauthorized", ErrUnauthorized, CodeUnauthorized},
		{"forbidden", ErrForbidden, CodeForbidden},
		{"not found", ErrNotFound, CodeNotFound},
		{"version conflict", NewVersionConflict(1), CodeVersionConflict},
		{"ordinary conflict", ErrConflict, CodeConflict},
		{"immutable", ErrImmutable, CodeEvidenceImmutable},
		{"idempotency key reused", ErrIdempotencyConflict, CodeIdempotencyKeyReused},
		{"idempotency in progress", ErrIdempotencyInProgress, CodeIdempotencyInProgress},
		{"idempotency failed", ErrIdempotencyFailed, CodeIdempotencyRequestFailed},
		{"full verification unavailable", ErrFullVerificationUnavailable, CodeCosignFullVerificationUnavailable},
		{"verification failed", ErrVerificationFailed, CodeVerificationFailed},
		{"rate limited", ErrRateLimited, CodeRateLimited},
		{"signing provider unavailable", ErrRetryableSigning, CodeSigningProviderUnavailable},
		{"dependency unavailable", ErrDependencyUnavailable, CodeDependencyUnavailable},
		{"unknown cause", fmt.Errorf("storage failure: %w", errors.New("postgres://secret@db.invalid")), CodeInternalError},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			details := DescribeProblem(testCase.err)
			if details.Code != testCase.code {
				t.Fatalf("code = %q, want %q", details.Code, testCase.code)
			}
			if details.Detail == "" || containsSensitiveProblemText(details.Detail) {
				t.Fatalf("unsafe detail %q for %q", details.Detail, testCase.name)
			}
		})
	}
}

func containsSensitiveProblemText(value string) bool {
	return len(value) == 0 || containsAny(value, "super-secret", "provider.example.invalid", "token=")
}

func containsAny(value string, forbidden ...string) bool {
	for _, item := range forbidden {
		if len(item) != 0 && contains(value, item) {
			return true
		}
	}
	return false
}

func contains(value, item string) bool {
	for index := 0; index+len(item) <= len(value); index++ {
		if value[index:index+len(item)] == item {
			return true
		}
	}
	return false
}
