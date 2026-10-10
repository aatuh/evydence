package httpapi

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type customerArchiveCommandFixture struct {
	value packagedomain.CustomerSecurityPackage
	calls int
}

func (f *customerArchiveCommandFixture) AccessCustomerSecurityPackage(context.Context, domain.Actor, string) (packagedomain.CustomerSecurityPackage, error) {
	f.calls++
	return f.value, nil
}
func (*customerArchiveCommandFixture) SecurityReviewPackageReport(context.Context, domain.Actor, string) (packagedomain.SecurityReviewPackageReport, error) {
	panic("archive path requested an unrelated report")
}
func (f *customerArchiveCommandFixture) AccessPortalPackage(_ context.Context, _ string, _ packageapp.PortalAcceptanceInput, download bool) (packagedomain.CustomerSecurityPackage, error) {
	if !download {
		panic("archive path requested an unaudited portal view")
	}
	f.calls++
	return f.value, nil
}

func TestCustomerAndPortalArchiveBoundariesUseOwnedRendererAndMapSafeFailures(t *testing.T) {
	server, secret := testServer(t)
	f := &customerArchiveCommandFixture{value: packagedomain.CustomerSecurityPackage{ID: "package", Title: "Scoped package", Manifest: map[string]any{"public": "recorded"}}}
	server.customerPackageAccessCommands, server.portalTokenCommands = f, f
	for _, render := range []func() (packageapp.CustomerPackageArchive, error){
		func() (packageapp.CustomerPackageArchive, error) {
			return server.customerPackageArchive(t.Context(), domain.Actor{TenantID: "tenant"}, f.value.ID)
		},
		func() (packageapp.CustomerPackageArchive, error) {
			return server.portalArchive(t.Context(), "opaque-token", packageapp.PortalAcceptanceInput{})
		},
	} {
		want, err := packageapp.RenderCustomerPackageArchive(f.value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := render()
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("archive boundary did not consume the owned frozen record", err)
		}
		f.value.Manifest["api_key"] = "private-archive-canary"
		if value, err := render(); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(value, packageapp.CustomerPackageArchive{}) {
			t.Fatal("unsafe render lost public error class or returned partial bytes", err)
		}
		delete(f.value.Manifest, "api_key")
	}
	if f.calls != 4 {
		t.Fatal("archive rendering invoked extra access or skipped the committed access port", f.calls)
	}
	response := getRaw(t, server, secret, "/v1/customer-packages/package/download", http.StatusOK)
	want, err := packageapp.RenderCustomerPackageArchive(f.value)
	if err != nil || !reflect.DeepEqual(response.Body.Bytes(), want.Bytes) || response.Header().Get("Content-Type") != "application/zip" || response.Header().Get("Content-Length") != strconv.Itoa(len(want.Bytes)) || response.Header().Get("X-Evydence-Archive-Hash") != want.Hash || response.Header().Get("Content-Disposition") != `attachment; filename="evydence-customer-package-package.zip"` {
		t.Fatal("owned archive response lost bytes or headers", err)
	}
	f.value.Manifest["api_key"] = "private-archive-canary"
	response = getRaw(t, server, secret, "/v1/customer-packages/package/download", http.StatusBadRequest)
	if strings.Contains(response.Body.String(), "private-archive-canary") || strings.Contains(response.Body.String(), "sensitive field") {
		t.Fatal("archive Problem Details disclosed rendering internals")
	}
}
