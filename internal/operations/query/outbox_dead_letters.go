package query

import (
	"context"
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// OutboxDeadLetter is an operator projection. It deliberately has no tenant,
// subject, payload, credential, raw error or execution-trace fields.
type OutboxDeadLetter struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	Status       string    `json:"status"`
	Attempts     int       `json:"attempts"`
	MaxAttempts  int       `json:"max_attempts"`
	FailureClass string    `json:"failure_class"`
	FailureCode  string    `json:"failure_code"`
	CreatedAt    time.Time `json:"created_at"`
	TerminalAt   time.Time `json:"terminal_at"`
}

// Reserve space for the bounded shared cursor and envelope metadata.
const MaxOutboxDeadLetterPageBytes = (1 << 20) - 8192

type OutboxDeadLetterReader interface {
	ReadOutboxDeadLettersPage(context.Context, appquery.PageRequest, *appquery.SortKey) (appquery.Result[OutboxDeadLetter], error)
}

func ValidateOutboxDeadLetterPage(page appquery.PageRequest, after *appquery.SortKey) error {
	if appquery.Validate(page, after) != nil || page.Sort != appquery.SortID {
		return ErrValidation
	}
	if after != nil && (after.Value != after.ID || !validOutboxDeadLetterID(after.ID)) {
		return ErrValidation
	}
	return nil
}

func validOutboxDeadLetterID(id string) bool {
	return id != "" && len(id) <= 1024 && utf8.ValidString(id) && !strings.ContainsFunc(id, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) })
}

func validOutboxCode(code string) bool {
	if code == "" || len(code) > 96 {
		return false
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// ValidateOutboxDeadLetter checks the closed operational projection, including
// historical rows that predate today's worker failure-code validation.
func ValidateOutboxDeadLetter(item OutboxDeadLetter) error {
	if !validOutboxDeadLetterID(item.ID) || !validOutboxCode(item.Kind) || !validOutboxCode(item.FailureCode) || item.Status != "dead_letter" || item.Attempts < 0 || item.MaxAttempts < 1 || item.Attempts > item.MaxAttempts || item.CreatedAt.IsZero() || item.TerminalAt.IsZero() || (item.FailureClass != "transient" && item.FailureClass != "permanent" && item.FailureClass != "poisoned") {
		return ErrInvalidProjection
	}
	return nil
}

func (s *OutboxDiagnostics) DeadLettersPage(ctx context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[OutboxDeadLetter], error) {
	var empty appquery.Result[OutboxDeadLetter]
	if s == nil || ctx == nil {
		return empty, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionOutboxDiagnosticsRead}); err != nil {
		return empty, err
	}
	if err := ValidateOutboxDeadLetterPage(page, after); err != nil {
		return empty, err
	}
	result, err := s.reader.ReadOutboxDeadLettersPage(ctx, page, after)
	if err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := authz.Authorize(ctx, actor, authz.Request{Action: authz.ActionOutboxDiagnosticsRead}); err != nil {
		return empty, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) != page.PageSize || result.Next.Value != result.Next.ID || result.Next.ID != result.Items[len(result.Items)-1].ID) {
		return empty, ErrInvalidProjection
	}
	items := make([]OutboxDeadLetter, 0, len(result.Items))
	var previous string
	if after != nil {
		previous = after.ID
	}
	size := 0
	for _, item := range result.Items {
		if ValidateOutboxDeadLetter(item) != nil {
			return empty, ErrInvalidProjection
		}
		if previous != "" && ((page.Direction == appquery.Ascending && item.ID <= previous) || (page.Direction == appquery.Descending && item.ID >= previous)) {
			return empty, ErrInvalidProjection
		}
		previous = item.ID
		item.CreatedAt, item.TerminalAt = item.CreatedAt.UTC(), item.TerminalAt.UTC()
		raw, err := json.Marshal(item)
		if err != nil || len(raw)+1 > MaxOutboxDeadLetterPageBytes-size {
			return empty, ErrInvalidProjection
		}
		size += len(raw) + 1
		items = append(items, item)
	}
	var next *appquery.SortKey
	if result.Next != nil {
		key := *result.Next
		next = &key
	}
	return appquery.Result[OutboxDeadLetter]{Items: items, Next: next}, nil
}
