package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/api-toolkit/v3/httpx"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
)

const (
	pageSizeParameter  = "page_size"
	cursorParameter    = "cursor"
	sortParameter      = "sort"
	directionParameter = "direction"
)

type pageRequest struct {
	pageSize  int
	sort      appquery.Sort
	direction appquery.Direction
	after     *appquery.SortKey
	filters   string
}

// parsePageRequest validates the full query surface before it reaches an
// application query. Cursor tokens are bound to the actor tenant, route,
// active filters, and requested ordering to prevent accidental cross-query
// continuation even when a caller legitimately holds multiple cursors.
func (s *Server) parsePageRequest(r *http.Request, actor domain.Actor, resource string, filters ...string) (pageRequest, error) {
	return s.parsePageRequestWithLegacyLimit(r, actor, resource, false, filters...)
}

func (s *Server) parsePageRequestWithLegacyLimit(r *http.Request, actor domain.Actor, resource string, acceptLegacyLimit bool, filters ...string) (pageRequest, error) {
	if r == nil || actor.TenantID == "" || resource == "" {
		return pageRequest{}, app.ErrValidation
	}
	allowed := map[string]bool{
		pageSizeParameter:  true,
		cursorParameter:    true,
		sortParameter:      true,
		directionParameter: true,
	}
	for _, filter := range filters {
		if filter == "" || allowed[filter] {
			return pageRequest{}, app.ErrValidation
		}
		allowed[filter] = true
	}
	if acceptLegacyLimit {
		allowed["limit"] = true
	}
	queryValues, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return pageRequest{}, app.ErrValidation
	}
	for key, values := range queryValues {
		if !allowed[key] || len(values) != 1 || strings.TrimSpace(values[0]) == "" {
			return pageRequest{}, app.ErrValidation
		}
	}
	pageSize := appquery.DefaultPageSize
	if _, hasPageSize := queryValues[pageSizeParameter]; hasPageSize && acceptLegacyLimit && len(queryValues["limit"]) != 0 {
		return pageRequest{}, app.ErrValidation
	}
	if raw, ok := queryValues[pageSizeParameter]; ok {
		parsed, err := strconv.Atoi(raw[0])
		if err != nil || parsed < 1 || parsed > appquery.MaxPageSize || strconv.Itoa(parsed) != raw[0] {
			return pageRequest{}, app.ErrValidation
		}
		pageSize = parsed
	} else if acceptLegacyLimit {
		if raw, ok := queryValues["limit"]; ok {
			parsed, err := strconv.Atoi(raw[0])
			if err != nil || parsed < 1 || parsed > appquery.MaxPageSize || strconv.Itoa(parsed) != raw[0] {
				return pageRequest{}, app.ErrValidation
			}
			pageSize = parsed
		}
	}
	sortField, direction, allowedSorts := paginationOptions(resource)
	if raw, ok := queryValues[sortParameter]; ok {
		sortField = appquery.Sort(raw[0])
		if !allowedSorts[sortField] {
			return pageRequest{}, app.ErrValidation
		}
	}
	if raw, ok := queryValues[directionParameter]; ok {
		direction = appquery.Direction(raw[0])
		if direction != appquery.Ascending && direction != appquery.Descending {
			return pageRequest{}, app.ErrValidation
		}
	}
	filterHash := filterFingerprint(queryValues, filters)
	request := pageRequest{pageSize: pageSize, sort: sortField, direction: direction, filters: filterHash}
	if raw, ok := queryValues[cursorParameter]; ok {
		cursor, err := s.cursors.Decode(raw[0])
		if err != nil || cursor.TenantID != actor.TenantID || cursor.Resource != resource || cursor.Filters != filterHash || cursor.Sort != sortField || cursor.Direction != direction {
			return pageRequest{}, app.ErrValidation
		}
		request.after = &cursor.Key
	}
	return request, nil
}

func paginationOptions(resource string) (appquery.Sort, appquery.Direction, map[appquery.Sort]bool) {
	switch resource {
	case "control-framework-template-packs", "sbom-components":
		return appquery.SortID, appquery.Ascending, map[appquery.Sort]bool{appquery.SortID: true}
	case "evidence-search", "audit-log":
		return appquery.SortCreatedAt, appquery.Descending, map[appquery.Sort]bool{
			appquery.SortCreatedAt: true,
			appquery.SortID:        true,
		}
	default:
		return appquery.SortCreatedAt, appquery.Ascending, map[appquery.Sort]bool{
			appquery.SortCreatedAt: true,
			appquery.SortID:        true,
		}
	}
}

func filterFingerprint(values map[string][]string, filters []string) string {
	sortedFilters := append([]string(nil), filters...)
	sort.Strings(sortedFilters)
	hash := sha256.New()
	for _, filter := range sortedFilters {
		value := ""
		if raw, ok := values[filter]; ok && len(raw) == 1 {
			value = raw[0]
		}
		_, _ = hash.Write([]byte(filter))
		_, _ = hash.Write([]byte{'='})
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func writePaginated[T any](s *Server, w http.ResponseWriter, r *http.Request, actor domain.Actor, resource string, filters []string, items []T, keyOf func(T, appquery.Sort) appquery.SortKey) {
	writePaginatedWithLegacyLimit(s, w, r, actor, resource, filters, false, items, keyOf)
}

func writePaginatedWithLegacyLimit[T any](s *Server, w http.ResponseWriter, r *http.Request, actor domain.Actor, resource string, filters []string, acceptLegacyLimit bool, items []T, keyOf func(T, appquery.Sort) appquery.SortKey) {
	request, err := s.parsePageRequestWithLegacyLimit(r, actor, resource, acceptLegacyLimit, filters...)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	page, err := appquery.Page(items, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after, keyOf)
	if err != nil {
		writeProblem(w, r, app.ErrValidation)
		return
	}
	writePage(s, w, r, actor, resource, request, page)
}

func writePage[T any](s *Server, w http.ResponseWriter, r *http.Request, actor domain.Actor, resource string, request pageRequest, page appquery.Result[T]) {
	meta := map[string]any{
		"api_version": "v1",
		"page_size":   request.pageSize,
		"sort":        request.sort,
		"direction":   request.direction,
	}
	if page.Next != nil {
		next, err := s.cursors.Encode(appquery.Cursor{
			TenantID:  actor.TenantID,
			Resource:  resource,
			Filters:   request.filters,
			Sort:      request.sort,
			Direction: request.direction,
			Key:       *page.Next,
		})
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		meta["next_cursor"] = next
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"data": page.Items, "meta": meta})
}

func writeCreatedAtPaginated[T any](s *Server, w http.ResponseWriter, r *http.Request, actor domain.Actor, resource string, filters []string, items []T, identity func(T) (string, time.Time)) {
	writePaginated(s, w, r, actor, resource, filters, items, func(item T, sort appquery.Sort) appquery.SortKey {
		id, createdAt := identity(item)
		return appquery.RecordSortKey(id, createdAt, sort)
	})
}

func writeCreatedAtPaginatedWithLegacyLimit[T any](s *Server, w http.ResponseWriter, r *http.Request, actor domain.Actor, resource string, filters []string, items []T, identity func(T) (string, time.Time)) {
	writePaginatedWithLegacyLimit(s, w, r, actor, resource, filters, true, items, func(item T, sort appquery.Sort) appquery.SortKey {
		id, createdAt := identity(item)
		return appquery.RecordSortKey(id, createdAt, sort)
	})
}
