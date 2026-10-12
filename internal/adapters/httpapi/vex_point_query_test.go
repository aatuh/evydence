package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type vexPointQueryFake struct {
	actor       identitydomain.Actor
	id          string
	docCalls    int
	reportCalls int
	err         error
}

func (f *vexPointQueryFake) GetVEXDocument(_ context.Context, actor identitydomain.Actor, id string) (evidencedomain.VEXDocument, error) {
	f.docCalls++
	f.actor, f.id = actor, id
	if f.err != nil {
		return evidencedomain.VEXDocument{}, f.err
	}
	return evidencedomain.VEXDocument{ID: id, TenantID: actor.TenantID, EvidenceID: "ev_1", ReleaseID: "rel_1", Format: "openvex", Author: "author", SchemaVersion: "vex-document.v1", CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}, nil
}

func (f *vexPointQueryFake) GetVEXImportReport(_ context.Context, actor identitydomain.Actor, id string) (evidencedomain.VEXImportReport, error) {
	f.reportCalls++
	f.actor, f.id = actor, id
	if f.err != nil {
		return evidencedomain.VEXImportReport{}, f.err
	}
	return evidencedomain.VEXImportReport{
		ID: "report_1", TenantID: actor.TenantID, VEXDocumentID: id, EvidenceID: "ev_1", ReleaseID: "rel_1",
		ParserVersion: "openvex.v1", Status: "parsed", MappingFailures: []evidencedomain.VEXImportIssue{{StatementIndex: 1, Code: "unmatched", Detail: "No match."}},
		SchemaVersion: "vex-import-report.v1", CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}, nil
}

func TestVEXHandlersUseFocusedPointsAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &vexPointQueryFake{}
	server.vexPointQuery = query
	response := getRaw(t, server, secret, "/v1/vex/vex_database", http.StatusOK)
	if !strings.Contains(response.Body.String(), `"format":"openvex"`) || query.id != "vex_database" || query.actor.TenantID == "" || query.docCalls != 1 {
		t.Fatalf("document response=%s query=%#v", response.Body.String(), query)
	}
	response = getRaw(t, server, secret, "/v1/vex/vex_database/import-report", http.StatusOK)
	if !strings.Contains(response.Body.String(), `"code":"unmatched"`) || query.id != "vex_database" || query.reportCalls != 1 {
		t.Fatalf("report response=%s query=%#v", response.Body.String(), query)
	}
	getRawNoAuth(t, server, "/v1/vex/vex_database", http.StatusUnauthorized)
	getRawNoAuth(t, server, "/v1/vex/vex_database/import-report", http.StatusUnauthorized)
	if query.docCalls != 1 || query.reportCalls != 1 {
		t.Fatalf("unauthenticated query calls=%#v", query)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{evidencequery.ErrValidation, http.StatusBadRequest},
		{evidencequery.ErrNotFound, http.StatusNotFound},
		{evidencequery.ErrConflict, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-vex-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		for _, path := range []string{"/v1/vex/vex_database", "/v1/vex/vex_database/import-report"} {
			response := getRaw(t, server, secret, path, test.status)
			if strings.Contains(response.Body.String(), "private-vex-database-detail") {
				t.Fatalf("internal detail leaked: %s", response.Body.String())
			}
		}
	}
}
