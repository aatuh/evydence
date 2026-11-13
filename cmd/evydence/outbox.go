package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	appquery "github.com/aatuh/evydence/internal/app/query"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
	"github.com/aatuh/evydence/internal/platform/config"
)

var (
	errOutboxArguments = errors.New("usage: evydence outbox backlog --url URL | evydence outbox dead-letters --url URL [--page-size N --direction asc|desc --cursor TOKEN] | evydence outbox replay --url URL --job-id ID --idempotency-key KEY")
	errOutboxResponse  = errors.New("outbox API response is invalid")
	errOutboxRequest   = errors.New("outbox API request failed")
)

// Reject ambiguous repeated flags without echoing operator-supplied values.
type outboxStringFlag struct {
	value string
	set   bool
}

func (v *outboxStringFlag) String() string {
	if v == nil {
		return ""
	}
	return v.value
}

func (v *outboxStringFlag) Set(value string) error {
	if v.set {
		return errOutboxArguments
	}
	v.value, v.set = value, true
	return nil
}

type outboxBacklog struct {
	PendingJobs            *int      `json:"pending_jobs"`
	RunningJobs            *int      `json:"running_jobs"`
	TerminalJobs           *int      `json:"terminal_jobs"`
	OldestPendingCreatedAt time.Time `json:"oldest_pending_created_at,omitempty"`
}

type outboxReplayResult struct {
	JobID      string    `json:"job_id"`
	Status     string    `json:"status"`
	ReplayedAt time.Time `json:"replayed_at"`
}

func validOutboxJobID(id string) bool {
	return id != "" && id != "." && id != ".." && len(id) <= 1024 && utf8.ValidString(id) &&
		!strings.ContainsAny(id, "/\\") && !strings.ContainsFunc(id, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) })
}

func validOutboxOperationKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for _, b := range []byte(key) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func runOutboxCLI(ctx context.Context, input cliInput, args []string, output, diagnostics io.Writer) error {
	if len(args) == 0 || (args[0] != "backlog" && args[0] != "replay" && args[0] != "dead-letters") {
		return errOutboxArguments
	}
	fs := flag.NewFlagSet("outbox "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var endpoint, credential, jobID, operation outboxStringFlag
	pageSize := outboxStringFlag{value: strconv.Itoa(appquery.DefaultPageSize)}
	direction := outboxStringFlag{value: string(appquery.Ascending)}
	var cursor outboxStringFlag
	fs.Var(&endpoint, "url", "Evydence API URL")
	fs.Var(&credential, "api-key", "Evydence API key; a private credential file is also supported")
	switch args[0] {
	case "replay":
		fs.Var(&jobID, "job-id", "Terminal job to replay")
		fs.Var(&operation, "idempotency-key", "Explicit operation key; reuse the same key when retrying")
	case "dead-letters":
		fs.Var(&pageSize, "page-size", "Maximum records, from 1 through 500 (default 50)")
		fs.Var(&direction, "direction", "ID ordering: asc (default) or desc")
		fs.Var(&cursor, "cursor", "Opaque next_cursor from the preceding page")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err := fmt.Fprintln(output, errOutboxArguments.Error())
			return err
		}
		return errOutboxArguments
	}
	if fs.NArg() != 0 || args[0] == "replay" && (!validOutboxJobID(jobID.value) || !validOutboxOperationKey(operation.value)) {
		return errOutboxArguments
	}
	pageLimit, err := strconv.Atoi(pageSize.value)
	if args[0] == "dead-letters" && (err != nil || strconv.Itoa(pageLimit) != pageSize.value || pageLimit < 1 || pageLimit > appquery.MaxPageSize || (direction.value != "asc" && direction.value != "desc") || cursor.set && !validOutboxCursor(cursor.value)) {
		return errOutboxArguments
	}
	return runConfiguredCLI(ctx, input, diagnostics, fs, config.CLIOutbox, func(ctx context.Context, settings config.CLISettings) error {
		if settings.APIURL == "" || settings.APIKey.Reveal() == "" {
			return errCLIConfiguration
		}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		// A redirect is an unsuccessful request, never authority to forward an
		// operator credential or replay mutation to a replacement endpoint.
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		var body []byte
		var err error
		switch args[0] {
		case "backlog":
			body, err = getEvydence(requestCtx, client, settings.APIURL, settings.APIKey.Reveal(), "/v1/admin/outbox")
		case "dead-letters":
			query := url.Values{"page_size": {pageSize.value}, "direction": {direction.value}}
			if cursor.set {
				query.Set("cursor", cursor.value)
			}
			body, err = getEvydence(requestCtx, client, settings.APIURL, settings.APIKey.Reveal(), "/v1/admin/outbox/dead-letters?"+query.Encode())
		case "replay":
			body, err = postRawEvydence(requestCtx, client, settings.APIURL, settings.APIKey.Reveal(), "/v1/admin/outbox/"+url.PathEscape(jobID.value)+"/replay", operation.value, []byte(`{}`))
		}
		if err != nil {
			return outboxRequestError(err)
		}
		if rejectDuplicateJSONKeys(body, "outbox response") != nil {
			return errOutboxResponse
		}
		if args[0] == "dead-letters" {
			return writeOutboxDeadLetterPage(output, body, pageLimit, direction.value)
		}
		if args[0] == "backlog" {
			var response struct {
				Data *outboxBacklog `json:"data"`
			}
			if json.Unmarshal(body, &response) != nil || response.Data == nil {
				return errOutboxResponse
			}
			data := response.Data
			if data.PendingJobs == nil || data.RunningJobs == nil || data.TerminalJobs == nil ||
				*data.PendingJobs < 0 || *data.RunningJobs < 0 || *data.TerminalJobs < 0 ||
				(*data.PendingJobs > 0) == data.OldestPendingCreatedAt.IsZero() {
				return errOutboxResponse
			}
			return json.NewEncoder(output).Encode(response)
		}
		var response struct {
			Data *outboxReplayResult `json:"data"`
		}
		if json.Unmarshal(body, &response) != nil || response.Data == nil || response.Data.JobID != jobID.value || response.Data.Status != "queued" || response.Data.ReplayedAt.IsZero() {
			return errOutboxResponse
		}
		return json.NewEncoder(output).Encode(response)
	})
}

func validOutboxCursor(cursor string) bool {
	return cursor != "" && len(cursor) <= 4096 && utf8.ValidString(cursor) && !strings.ContainsFunc(cursor, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) })
}

func writeOutboxDeadLetterPage(output io.Writer, body []byte, pageSize int, direction string) error {
	var response struct {
		Data []operationsquery.OutboxDeadLetter `json:"data"`
		Meta *struct {
			APIVersion string `json:"api_version"`
			PageSize   int    `json:"page_size"`
			Sort       string `json:"sort"`
			Direction  string `json:"direction"`
			NextCursor string `json:"next_cursor,omitempty"`
		} `json:"meta"`
	}
	if json.Unmarshal(body, &response) != nil || response.Data == nil || response.Meta == nil || len(response.Data) > pageSize {
		return errOutboxResponse
	}
	meta := response.Meta
	if meta.APIVersion != "v1" || meta.PageSize != pageSize || meta.Sort != "id" || meta.Direction != direction || meta.NextCursor != "" && (!validOutboxCursor(meta.NextCursor) || len(response.Data) != pageSize) {
		return errOutboxResponse
	}
	previous := ""
	for _, item := range response.Data {
		if operationsquery.ValidateOutboxDeadLetter(item) != nil || previous != "" && ((direction == "asc" && item.ID <= previous) || (direction == "desc" && item.ID >= previous)) {
			return errOutboxResponse
		}
		previous = item.ID
	}
	return json.NewEncoder(output).Encode(response)
}

func outboxRequestError(err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.Join(errOutboxRequest, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(errOutboxRequest, context.DeadlineExceeded)
	}
	var requestError apiRequestError
	if errors.As(err, &requestError) {
		return fmt.Errorf("outbox API request failed (HTTP %d)", requestError.status)
	}
	return errOutboxRequest
}
