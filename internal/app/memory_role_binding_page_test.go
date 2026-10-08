package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

func TestMemoryRoleBindingPagesFilterBeforeProjectingSelectedMetadata(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Identity.(identityquery.RoleBindingReader)
	if !ok {
		t.Fatal("memory identity lacks focused role-binding page reader")
	}
	at := fixedNow()
	for _, id := range []string{"a", "b", "c"} {
		tx.state.RoleBindings[id] = domain.RoleBinding{ID: id, TenantID: "tenant", SubjectType: "user", SubjectID: "tenant-user", Role: "security_engineer", ResourceType: "product", ResourceID: "tenant-product", SchemaVersion: domain.RoleBindingSchemaVersion, CreatedAt: at}
	}
	tx.state.RoleBindings["foreign"] = domain.RoleBinding{ID: "foreign", TenantID: "foreign", SubjectID: strings.Repeat("private", 100000)}
	req := identityquery.RoleBindingPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	before := make(map[string]domain.RoleBinding, len(tx.state.RoleBindings))
	for id, b := range tx.state.RoleBindings {
		before[id] = b
	}
	page, err := r.PageRoleBindings(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0] != identitydomain.RoleBinding(tx.state.RoleBindings["a"]) || page.Next == nil || page.Next.ID != "a" {
		t.Fatal("role page lost complete metadata, tenant filter or cursor", page, err)
	}
	req.After = page.Next
	page, err = r.PageRoleBindings(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "b" || page.Next == nil || page.Next.ID != "b" {
		t.Fatal("role cursor failed to advance", page, err)
	}
	req.Page.Direction, req.After = appquery.Descending, nil
	page, err = r.PageRoleBindings(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "c" || page.Next == nil {
		t.Fatal("descending role page failed", page, err)
	}
	req.Page.Sort = appquery.SortCreatedAt
	page, err = r.PageRoleBindings(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "c" || page.Next == nil || page.Next.Value != at.UTC().Format(time.RFC3339Nano) {
		t.Fatal("created-at role page lost canonical timestamp or ID tie-break", page, err)
	}
	req.Page.Sort = appquery.SortID
	bad := tx.state.RoleBindings["a"]
	bad.SubjectID = strings.Repeat("x", 1025)
	tx.state.RoleBindings["a"] = bad
	before["a"] = bad
	if _, err := r.PageRoleBindings(t.Context(), req); err != nil {
		t.Fatal("role page projected unselected oversized metadata", err)
	}
	req.Page.Direction = appquery.Ascending
	if v, err := r.PageRoleBindings(t.Context(), req); !errors.Is(err, identityquery.ErrInvalidProjection) || !reflect.DeepEqual(v, appquery.Result[identitydomain.RoleBinding]{}) {
		t.Fatal("selected corrupt role produced partial page", v, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.PageRoleBindings(ctx, req); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, appquery.Result[identitydomain.RoleBinding]{}) {
		t.Fatal("cancelled role read returned data", v, err)
	}
	if !reflect.DeepEqual(before, tx.state.RoleBindings) {
		t.Fatal("role read changed state")
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PageRoleBindings(t.Context(), req); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction returned role page", err)
	}
}
