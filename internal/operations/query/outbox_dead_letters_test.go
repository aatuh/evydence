package query

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type deadLetterReaderFake struct {
	result appquery.Result[OutboxDeadLetter]
	err    error
	reads  int
	page   appquery.PageRequest
	after  *appquery.SortKey
	onRead func()
}

func (f *deadLetterReaderFake) ReadOutboxCounts(context.Context) (OutboxCounts, error) {
	return OutboxCounts{}, nil
}
func (f *deadLetterReaderFake) ReadOutboxDeadLettersPage(_ context.Context, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[OutboxDeadLetter], error) {
	f.reads++
	f.page, f.after = page, after
	if f.onRead != nil {
		f.onRead()
	}
	return f.result, f.err
}
func validDeadLetter(id string) OutboxDeadLetter {
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	return OutboxDeadLetter{ID: id, Kind: "parse_sbom", Status: "dead_letter", Attempts: 2, MaxAttempts: 5, FailureClass: "permanent", FailureCode: "invalid_document", CreatedAt: at.Add(-time.Hour), TerminalAt: at}
}
func deadLetterAdmin() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"instance:admin"}}
}
func deadLetterPage() appquery.PageRequest {
	return appquery.PageRequest{PageSize: 2, Sort: appquery.SortID, Direction: appquery.Ascending}
}

func TestOutboxDeadLettersRequireCurrentInstanceAuthorityBeforeReadAndOutput(t *testing.T) {
	reader := &deadLetterReaderFake{result: appquery.Result[OutboxDeadLetter]{Items: []OutboxDeadLetter{validDeadLetter("job_a")}}}
	service, err := NewOutboxDiagnostics(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []identitydomain.Actor{{}, {TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}, {TenantID: "other", KeyID: "key", Scopes: []string{"admin"}}} {
		page, err := service.DeadLettersPage(t.Context(), actor, deadLetterPage(), nil)
		want := application.ErrForbidden
		if actor.TenantID == "" {
			want = application.ErrUnauthorized
		}
		if !errors.Is(err, want) || len(page.Items) != 0 || reader.reads != 0 {
			t.Fatal("tenant or missing authority reached global dead-letter metadata", err)
		}
	}
	actor := deadLetterAdmin()
	result, err := service.DeadLettersPage(t.Context(), actor, deadLetterPage(), nil)
	if err != nil || len(result.Items) != 1 || reader.reads != 1 || reader.page != deadLetterPage() {
		t.Fatal("authorized bounded page was lost", err)
	}
	reader.onRead = func() { actor.Scopes[0] = "admin" }
	result, err = service.DeadLettersPage(t.Context(), actor, deadLetterPage(), nil)
	if !errors.Is(err, application.ErrForbidden) || len(result.Items) != 0 || reader.reads != 2 {
		t.Fatal("revoked instance authority received a selected page", err)
	}
}

func TestOutboxDeadLettersRejectInvalidPageBeforeRead(t *testing.T) {
	reader := &deadLetterReaderFake{}
	service, err := NewOutboxDiagnostics(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		page  appquery.PageRequest
		after *appquery.SortKey
	}{
		{appquery.PageRequest{}, nil}, {appquery.PageRequest{PageSize: 501, Sort: appquery.SortID, Direction: appquery.Ascending}, nil},
		{appquery.PageRequest{PageSize: 2, Sort: appquery.SortCreatedAt, Direction: appquery.Ascending}, nil},
		{deadLetterPage(), &appquery.SortKey{Value: "wrong", ID: "job_a"}},
		{deadLetterPage(), &appquery.SortKey{Value: "bad\n", ID: "bad\n"}},
	} {
		if _, err := service.DeadLettersPage(t.Context(), deadLetterAdmin(), test.page, test.after); !errors.Is(err, ErrValidation) || reader.reads != 0 {
			t.Fatal("invalid page reached storage", err)
		}
	}
	if _, err := service.DeadLettersPage(nil, deadLetterAdmin(), deadLetterPage(), nil); !errors.Is(err, ErrValidation) { //nolint:staticcheck // Invalid-input regression intentionally verifies a missing context fails closed.
		t.Fatal(err)
	}
	if _, err := (*OutboxDiagnostics)(nil).DeadLettersPage(t.Context(), deadLetterAdmin(), deadLetterPage(), nil); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}

func TestOutboxDeadLettersRejectCorruptOrOversizedProjectionWithoutPartialOutput(t *testing.T) {
	for name, change := range map[string]func(*appquery.Result[OutboxDeadLetter]){
		"wrong_status":      func(r *appquery.Result[OutboxDeadLetter]) { r.Items[0].Status = "running" },
		"unsafe_kind":       func(r *appquery.Result[OutboxDeadLetter]) { r.Items[0].Kind = "PRIVATE payload" },
		"unsafe_code":       func(r *appquery.Result[OutboxDeadLetter]) { r.Items[0].FailureCode = "PRIVATE secret" },
		"unknown_class":     func(r *appquery.Result[OutboxDeadLetter]) { r.Items[0].FailureClass = "untrusted" },
		"negative_attempts": func(r *appquery.Result[OutboxDeadLetter]) { r.Items[0].Attempts = -1 },
		"excess_attempts":   func(r *appquery.Result[OutboxDeadLetter]) { r.Items[0].Attempts = 6 },
		"bad_maximum":       func(r *appquery.Result[OutboxDeadLetter]) { r.Items[0].MaxAttempts = 0 },
		"missing_time":      func(r *appquery.Result[OutboxDeadLetter]) { r.Items[0].TerminalAt = time.Time{} },
		"oversized_id":      func(r *appquery.Result[OutboxDeadLetter]) { r.Items[0].ID = strings.Repeat("x", 1025) },
		"duplicate_id":      func(r *appquery.Result[OutboxDeadLetter]) { r.Items[1].ID = r.Items[0].ID },
		"wrong_order":       func(r *appquery.Result[OutboxDeadLetter]) { r.Items[0], r.Items[1] = r.Items[1], r.Items[0] },
		"wrong_next":        func(r *appquery.Result[OutboxDeadLetter]) { r.Next = &appquery.SortKey{Value: "wrong", ID: "wrong"} },
		"too_many_rows":     func(r *appquery.Result[OutboxDeadLetter]) { r.Items = append(r.Items, validDeadLetter("job_c")) },
	} {
		t.Run(name, func(t *testing.T) {
			reader := &deadLetterReaderFake{result: appquery.Result[OutboxDeadLetter]{Items: []OutboxDeadLetter{validDeadLetter("job_a"), validDeadLetter("job_b")}}}
			change(&reader.result)
			service, err := NewOutboxDiagnostics(reader)
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.DeadLettersPage(t.Context(), deadLetterAdmin(), deadLetterPage(), nil)
			if !errors.Is(err, ErrInvalidProjection) || len(out.Items) != 0 || out.Next != nil {
				t.Fatal("corrupt page leaked partial metadata", err)
			}
		})
	}
	reader := &deadLetterReaderFake{}
	for i := range 500 {
		reader.result.Items = append(reader.result.Items, validDeadLetter(fmt.Sprintf("%04d", i)+strings.Repeat("<", 1000)))
	}
	service, err := NewOutboxDiagnostics(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := deadLetterPage()
	page.PageSize = 500
	if out, err := service.DeadLettersPage(t.Context(), deadLetterAdmin(), page, nil); !errors.Is(err, ErrInvalidProjection) || len(out.Items) != 0 {
		t.Fatal("encoded page bypassed the byte budget", err)
	}
}

func TestOutboxDeadLettersPreserveKeysetAndCancellation(t *testing.T) {
	after := appquery.SortKey{Value: "job_z", ID: "job_z"}
	next := appquery.SortKey{Value: "job_a", ID: "job_a"}
	reader := &deadLetterReaderFake{result: appquery.Result[OutboxDeadLetter]{Items: []OutboxDeadLetter{validDeadLetter("job_b"), validDeadLetter("job_a")}, Next: &next}}
	service, err := NewOutboxDiagnostics(reader)
	if err != nil {
		t.Fatal(err)
	}
	page := deadLetterPage()
	page.Direction = appquery.Descending
	out, err := service.DeadLettersPage(t.Context(), deadLetterAdmin(), page, &after)
	if err != nil || len(out.Items) != 2 || (reader.after == nil || *reader.after != after) || out.Next == nil || *out.Next != next {
		t.Fatal("descending keyset was changed", err)
	}
	next.ID = "changed"
	if out.Next.ID != "job_a" {
		t.Fatal("reader retained mutable cursor ownership")
	}
	reader.err = errors.New("PRIVATE database failure")
	if out, err := service.DeadLettersPage(t.Context(), deadLetterAdmin(), page, &after); err == nil || len(out.Items) != 0 {
		t.Fatal("failed read retained a partial result")
	}
	reader.err = nil
	reader.result = appquery.Result[OutboxDeadLetter]{}
	ctx, cancel := context.WithCancel(t.Context())
	reader.onRead = cancel
	if out, err := service.DeadLettersPage(ctx, deadLetterAdmin(), page, nil); !errors.Is(err, context.Canceled) || len(out.Items) != 0 {
		t.Fatal("canceled read published selected metadata", err)
	}
	reader.onRead = nil
	out, err = service.DeadLettersPage(t.Context(), deadLetterAdmin(), page, nil)
	if err != nil || out.Items == nil || out.Next != nil {
		t.Fatal("empty page did not retain array semantics", err)
	}
}
