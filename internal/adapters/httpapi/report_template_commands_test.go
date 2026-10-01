package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type reportTemplateHTTPFake struct {
	creates, renders int
	err              error
}

func (f *reportTemplateHTTPFake) CreateCustomReportTemplate(_ context.Context, actor identitydomain.Actor, input packageapp.CreateReportTemplateInput) (packagedomain.CustomReportTemplate, error) {
	f.creates++
	return packagedomain.CustomReportTemplate{ID: "tpl_focused", TenantID: actor.TenantID, Name: input.Name, Version: input.Version, ReportType: input.ReportType, AllowedFields: input.AllowedFields, Template: input.Template}, f.err
}
func (f *reportTemplateHTTPFake) RenderCustomReport(_ context.Context, actor identitydomain.Actor, input packageapp.RenderReportInput) (packagedomain.RenderedCustomReport, error) {
	f.renders++
	return packagedomain.RenderedCustomReport{ID: "render_focused", TenantID: actor.TenantID, TemplateID: input.TemplateID, SubjectType: input.SubjectType, SubjectID: input.SubjectID, Output: map[string]any{"subject_id": input.SubjectID}, Hash: "sha256:focused"}, f.err
}

func TestReportTemplateHandlersUseFocusedCommandsAndReplayResponses(t *testing.T) {
	server, secret := testServer(t)
	commands := &reportTemplateHTTPFake{}
	server.reportTemplateCommands = commands
	createPath := "/v1/report-templates"
	input := map[string]any{"name": "Focused", "version": "1", "report_type": "metadata", "allowed_fields": []string{"subject_id"}, "template": "inert"}
	response := postJSON(t, server, secret, createPath, "focused-template", input, http.StatusCreated)
	if dataField(t, response, "id") != "tpl_focused" || dataField(t, response, "name") != "Focused" || !strings.Contains(response, `"allowed_fields":["subject_id"]`) {
		t.Fatal(response)
	}
	replay := postJSON(t, server, secret, createPath, "focused-template", input, http.StatusCreated)
	if replay != response || commands.creates != 1 {
		t.Fatal("template replay reran command")
	}
	renderPath := "/v1/report-templates/tpl_focused/render"
	renderInput := map[string]any{"subject_type": "release", "subject_id": "rel_1"}
	response = postJSON(t, server, secret, renderPath, "focused-render", renderInput, http.StatusCreated)
	if dataField(t, response, "id") != "render_focused" || dataField(t, response, "template_id") != "tpl_focused" || !strings.Contains(response, `"output":{"subject_id":"rel_1"}`) {
		t.Fatal(response)
	}
	if replay := postJSON(t, server, secret, renderPath, "focused-render", renderInput, http.StatusCreated); replay != response || commands.renders != 1 {
		t.Fatal("render replay reran command")
	}
	for i, bad := range []string{`{"subject_type":"release","subject_id":3}`, `{"subject_type":"release","subject_id":"a","unknown":true}`, `{"subject_type":"release","subject_type":"other","subject_id":"a"}`, `null`, `[]`, `{"subject_type":"release","subject_id":"a"} {}`} {
		postRaw(t, server, secret, renderPath, "focused-bad-"+string(rune('a'+i)), []byte(bad), http.StatusBadRequest)
	}
	if commands.renders != 1 {
		t.Fatal("malformed input reached command")
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{packageapp.ErrNotFound, http.StatusNotFound}, {packageapp.ErrConflict, http.StatusConflict}, {packageapp.ErrValidation, http.StatusBadRequest}, {application.ErrForbidden, http.StatusForbidden}, {errors.New("private-template-db-detail"), http.StatusInternalServerError}} {
		commands.err = tc.err
		response := postJSON(t, server, secret, renderPath, "focused-error-"+string(rune('a'+i)), renderInput, tc.status)
		if strings.Contains(response, "private-template-db-detail") {
			t.Fatal("private error leaked")
		}
	}
}
