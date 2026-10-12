package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type answerLibraryQueryFake struct {
	calls  int
	after  *appquery.SortKey
	filter packagequery.AnswerLibraryFilter
	err    error
}

func (f *answerLibraryQueryFake) ListPage(_ context.Context, actor identitydomain.Actor, filter packagequery.AnswerLibraryFilter, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry], error) {
	f.calls++
	f.after = after
	f.filter = filter
	if f.err != nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, f.err
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	entry := packagedomain.QuestionnaireAnswerLibraryEntry{ID: "draft_1", TenantID: actor.TenantID, QuestionID: "q1", Answer: "reviewed draft", SchemaVersion: packagedomain.QuestionnaireAnswerLibraryVersion, CreatedAt: now}
	if after != nil {
		entry.ID = "draft_2"
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{Items: []packagedomain.QuestionnaireAnswerLibraryEntry{entry}}, nil
	}
	key := appquery.RecordSortKey(entry.ID, now, page.Sort)
	return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{Items: []packagedomain.QuestionnaireAnswerLibraryEntry{entry}, Next: &key}, nil
}

func TestAnswerLibraryHandlerUsesFocusedPageAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &answerLibraryQueryFake{}
	server.answerLibraryQuery = query
	first := getRaw(t, server, secret, "/v1/questionnaire-answer-library?question_id=q1&page_size=1", http.StatusOK)
	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "draft_1" || response.Meta.NextCursor == "" || query.filter.QuestionID != "q1" {
		t.Fatalf("first page=%s query=%#v error=%v", first.Body.String(), query, err)
	}
	second := getRaw(t, server, secret, "/v1/questionnaire-answer-library?question_id=q1&page_size=1&cursor="+url.QueryEscape(response.Meta.NextCursor), http.StatusOK)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Data[0].ID != "draft_2" || query.after == nil {
		t.Fatalf("second page=%s query=%#v error=%v", second.Body.String(), query, err)
	}
	for _, path := range []string{
		"/v1/questionnaire-answer-library?page_size=0",
		"/v1/questionnaire-answer-library?question_id=q1&question_id=q2",
		"/v1/questionnaire-answer-library?sort=unknown",
	} {
		getRaw(t, server, secret, path, http.StatusBadRequest)
	}
	getRawNoAuth(t, server, "/v1/questionnaire-answer-library", http.StatusUnauthorized)
	if query.calls != 2 {
		t.Fatalf("invalid request reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{packagequery.ErrValidation, http.StatusBadRequest},
		{packagequery.ErrNotFound, http.StatusNotFound},
		{packagequery.ErrInvalidProjection, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-answer-or-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		result := getRaw(t, server, secret, "/v1/questionnaire-answer-library", test.status)
		if strings.Contains(result.Body.String(), "private-answer-or-database-detail") {
			t.Fatalf("internal error leaked: %s", result.Body.String())
		}
	}
}
