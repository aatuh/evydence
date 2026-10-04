package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type customerArchiveHTTPFake struct {
	customerPackageAccessHTTPFake
	pkg   packagedomain.CustomerSecurityPackage
	actor identitydomain.Actor
	id    string
}

func (f *customerArchiveHTTPFake) AccessCustomerSecurityPackage(_ context.Context, a identitydomain.Actor, id string) (packagedomain.CustomerSecurityPackage, error) {
	f.calls++
	f.actor, f.id = a, id
	return f.pkg, f.err
}

func archiveEntries(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, entry := range reader.File {
		if out[entry.Name] != nil || strings.Contains(entry.Name, "/") || strings.Contains(entry.Name, "\\") || entry.UncompressedSize64 > 1<<20 {
			t.Fatal("unsafe or duplicate ZIP entry", entry.Name)
		}
		r, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
		closeErr := r.Close()
		if err != nil || closeErr != nil || len(content) > 1<<20 {
			t.Fatal("unbounded ZIP entry")
		}
		out[entry.Name] = content
	}
	return out
}

func TestCustomerArchiveUsesFocusedAccessAndFrozenRecord(t *testing.T) {
	s, secret := testServer(t)
	f := &customerArchiveHTTPFake{pkg: packagedomain.CustomerSecurityPackage{ID: "csp_archive", TenantID: "tenant", ProductID: "product", ReleaseID: "release", RedactionProfileID: "profile", Title: "Customer <script>bad</script>", State: "generated", Manifest: map[string]any{"evidence_ids": []string{"ev_frozen"}, "title": "Frozen"}, ManifestHash: "sha256:" + strings.Repeat("a", 64), DistributionWatermark: "reviewer watermark", ExpiresAt: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), CreatedAt: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), SchemaVersion: packagedomain.CustomerPackageSchemaVersion}}
	s.customerPackageAccessCommands = f
	s.ledger = nil
	s.packages = nil
	s.idempotency = nil
	w := getRaw(t, s, secret, "/v1/customer-packages/csp_archive/download", 200)
	if f.calls != 1 || f.id != "csp_archive" || f.actor.TenantID == "" || w.Header().Get("Content-Type") != "application/zip" || w.Header().Get("Content-Disposition") != `attachment; filename="evydence-customer-package-csp_archive.zip"` || w.Header().Get("Content-Length") != strconv.Itoa(w.Body.Len()) {
		t.Fatal("focused download/header contract differs")
	}
	digest := sha256.Sum256(w.Body.Bytes())
	if w.Header().Get("X-Evydence-Archive-Hash") != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("archive digest does not cover bytes")
	}
	entries := archiveEntries(t, w.Body.Bytes())
	if len(entries) != 6 {
		t.Fatal("archive entries changed", len(entries))
	}
	for _, name := range []string{"manifest.json", "package.json", "verification.json", "README.txt", "report.html", "WATERMARK.txt"} {
		if entries[name] == nil {
			t.Fatal("missing ZIP entry", name)
		}
	}
	var manifest, metadata map[string]any
	if json.Unmarshal(entries["manifest.json"], &manifest) != nil || manifest["title"] != "Frozen" || json.Unmarshal(entries["package.json"], &metadata) != nil || metadata["manifest_hash"] != f.pkg.ManifestHash || metadata["distribution_watermark"] != "reviewer watermark" {
		t.Fatal("frozen metadata altered")
	}
	if !bytes.Contains(entries["manifest.json"], []byte("ev_frozen")) || bytes.Contains(entries["report.html"], []byte("<script>bad</script>")) {
		t.Fatal("HTML is unsafe or manifest was rebuilt")
	}
	before := f.calls
	getRawNoAuth(t, s, "/v1/customer-packages/csp_archive/download", 401)
	if f.calls != before {
		t.Fatal("unauthenticated archive reached access command")
	}
}

func TestCustomerArchiveErrorsNeverPublishZIPOrPrivateDetails(t *testing.T) {
	s, secret := testServer(t)
	f := &customerArchiveHTTPFake{}
	s.customerPackageAccessCommands = f
	s.ledger = nil
	s.packages = nil
	for _, tc := range []struct {
		err    error
		status int
	}{{packageapp.ErrValidation, 400}, {application.ErrUnauthorized, 401}, {application.ErrForbidden, 403}, {packageapp.ErrNotFound, 404}, {packageapp.ErrConflict, 409}, {errors.New("private archive SQL secret"), 500}} {
		f.err = tc.err
		w := getRaw(t, s, secret, "/v1/customer-packages/csp_archive/download", tc.status)
		if w.Header().Get("Content-Disposition") != "" || w.Header().Get("X-Evydence-Archive-Hash") != "" || w.Header().Get("Content-Type") == "application/zip" || strings.Contains(w.Body.String(), "private archive SQL secret") {
			t.Fatal("failed access published ZIP/secret")
		}
	}
	f.err = nil
	f.pkg = packagedomain.CustomerSecurityPackage{ID: "csp_archive", Manifest: map[string]any{"token": "raw-private-canary"}}
	w := getRaw(t, s, secret, "/v1/customer-packages/csp_archive/download", 400)
	if strings.Contains(w.Body.String(), "raw-private-canary") || w.Header().Get("Content-Disposition") != "" || w.Header().Get("X-Evydence-Archive-Hash") != "" {
		t.Fatal("unsafe manifest escaped final archive boundary")
	}
}
