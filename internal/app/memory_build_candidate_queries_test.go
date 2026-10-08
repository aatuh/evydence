package app

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func memoryBuildCandidateQueryFixture(t *testing.T) (*memoryUnitOfWork, releasequery.BuildPointReader, releasequery.ReleaseCandidateReader) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	b, ok := tx.Repositories().Builds.(releasequery.BuildPointReader)
	if !ok {
		t.Fatal("memory builds lacks focused point reader")
	}
	c, ok := tx.Repositories().ReleaseCatalog.(releasequery.ReleaseCandidateReader)
	if !ok {
		t.Fatal("memory catalog lacks focused candidate reader")
	}
	at := fixedNow()
	tx.state.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", CollectorID: "collector", Provider: "github", CommitSHA: "commit", Repository: "owner/repo", WorkflowRef: "workflow", RunID: "42", RunAttempt: 2, JobID: "job", Actor: "actor", Ref: "main", OIDCSubject: "subject", Status: "succeeded", StartedAt: at, FinishedAt: &at, ParametersHash: "parameters", EnvironmentHash: "environment", SourceIdentity: map[string]any{"nested": map[string]any{"number": json.Number("9007199254740993"), "items": []any{"original"}}}, Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: "digest"}}, SchemaVersion: "build.v1", CreatedAt: at}
	tx.state.ReleaseCandidates["candidate"] = domain.ReleaseCandidate{ID: "candidate", TenantID: "tenant", ReleaseID: "tenant-release", Name: "Candidate", Revision: 3, State: "promoted", BuildIDs: []string{"build"}, ArtifactIDs: []string{"artifact"}, SBOMIDs: []string{"sbom"}, ScanIDs: []string{"scan"}, VEXIDs: []string{"vex"}, ContractIDs: []string{"contract"}, BundleIDs: []string{"bundle"}, SnapshotHash: "snapshot", SchemaVersion: "candidate.v1", CreatedAt: at, PromotedAt: &at, RejectedAt: &at}
	return tx, b, c
}

func TestMemoryBuildCandidatePointsPreserveCompleteDetachedMetadata(t *testing.T) {
	tx, b, c := memoryBuildCandidateQueryFixture(t)
	// Ownership joins must not decode unrelated parent metadata.
	p := tx.state.Products["tenant-product"]
	p.Name = strings.Repeat("x", 65537)
	tx.state.Products[p.ID] = p
	j := tx.state.Projects["tenant-project"]
	j.Name = p.Name
	tx.state.Projects[j.ID] = j
	r := tx.state.Releases["tenant-release"]
	r.State, r.Version = "unknown", p.Name
	tx.state.Releases[r.ID] = r
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	build, err := b.GetBuildPoint(t.Context(), "tenant", "build")
	if err != nil || build.ProductID != p.ID || !reflect.DeepEqual(build.Build, buildRunToReleaseContext(tx.state.BuildRuns["build"])) {
		t.Fatal("build point lost full current metadata or exact numeric identity", build, err)
	}
	candidate, err := c.GetReleaseCandidatePoint(t.Context(), "tenant", "candidate")
	want, parseErr := releaseCandidateToReleaseContext(tx.state.ReleaseCandidates["candidate"])
	if parseErr != nil || err != nil || candidate.ProductID != p.ID || !reflect.DeepEqual(candidate.Candidate, want) {
		t.Fatal("candidate point lost full current lifecycle and reference metadata", candidate, err)
	}
	*build.Build.FinishedAt = fixedNow().Add(time.Hour)
	build.Build.Outputs[0].Digest = "changed"
	nested := build.Build.SourceIdentity["nested"].(map[string]any)
	nested["number"] = json.Number("0")
	nested["items"].([]any)[0] = "changed"
	for _, ids := range [][]string{candidate.Candidate.BuildIDs, candidate.Candidate.ArtifactIDs, candidate.Candidate.SBOMIDs, candidate.Candidate.ScanIDs, candidate.Candidate.VEXIDs, candidate.Candidate.ContractIDs, candidate.Candidate.BundleIDs} {
		ids[0] = "changed"
	}
	*candidate.Candidate.PromotedAt, *candidate.Candidate.RejectedAt = fixedNow().Add(time.Hour), fixedNow().Add(time.Hour)
	after, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("point reads or caller mutations changed transaction state", err)
	}
}

func TestMemoryBuildCandidatePointsRejectForeignDanglingAndCrossProductParents(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*MemoryUnitOfWorkSnapshot)
	}{
		{"foreign-product", func(s *MemoryUnitOfWorkSnapshot) {
			p := s.Products["tenant-product"]
			p.TenantID = "foreign"
			s.Products[p.ID] = p
		}},
		{"missing-product", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Products, "tenant-product") }},
		{"foreign-release", func(s *MemoryUnitOfWorkSnapshot) {
			r := s.Releases["tenant-release"]
			r.TenantID = "foreign"
			s.Releases[r.ID] = r
		}},
		{"missing-release", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Releases, "tenant-release") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, b, c := memoryBuildCandidateQueryFixture(t)
			tc.mutate(&tx.state)
			if v, err := b.GetBuildPoint(t.Context(), "tenant", "build"); !errors.Is(err, releasequery.ErrNotFound) || !reflect.DeepEqual(v, releasequery.BuildPoint{}) {
				t.Fatal("build ownership join returned data", v, err)
			}
			if v, err := c.GetReleaseCandidatePoint(t.Context(), "tenant", "candidate"); !errors.Is(err, releasequery.ErrNotFound) || !reflect.DeepEqual(v, releasequery.ReleaseCandidatePoint{}) {
				t.Fatal("candidate ownership join returned data", v, err)
			}
		})
	}
	tx, b, c := memoryBuildCandidateQueryFixture(t)
	for _, project := range []string{"foreign-project", "missing-project"} {
		v := tx.state.BuildRuns["build"]
		v.ProjectID = project
		tx.state.BuildRuns[v.ID] = v
		if _, err := b.GetBuildPoint(t.Context(), "tenant", v.ID); !errors.Is(err, releasequery.ErrNotFound) {
			t.Fatal("build accepted foreign/dangling project", err)
		}
	}
	v := tx.state.BuildRuns["build"]
	v.ProjectID = "tenant-project"
	tx.state.BuildRuns[v.ID] = v
	tx.state.Products["other"] = domain.Product{ID: "other", TenantID: "tenant"}
	r := tx.state.Releases["tenant-release"]
	r.ProductID = "other"
	tx.state.Releases[r.ID] = r
	if _, err := b.GetBuildPoint(t.Context(), "tenant", v.ID); !errors.Is(err, releasequery.ErrNotFound) {
		t.Fatal("build combined unrelated products", err)
	}
	for _, tenant := range []string{"foreign", "missing"} {
		if v, err := b.GetBuildPoint(t.Context(), tenant, "build"); !errors.Is(err, releasequery.ErrNotFound) || !reflect.DeepEqual(v, releasequery.BuildPoint{}) {
			t.Fatal("build exposed foreign metadata", v, err)
		}
		if v, err := c.GetReleaseCandidatePoint(t.Context(), tenant, "candidate"); !errors.Is(err, releasequery.ErrNotFound) || !reflect.DeepEqual(v, releasequery.ReleaseCandidatePoint{}) {
			t.Fatal("candidate exposed foreign metadata", v, err)
		}
	}
}

func TestMemoryBuildCandidateQueriesRejectCorruptSelectedMetadataAndClosedContexts(t *testing.T) {
	tx, b, c := memoryBuildCandidateQueryFixture(t)
	original := tx.state.BuildRuns["build"]
	for _, mutate := range []func(*domain.BuildRun){
		func(v *domain.BuildRun) { v.SourceIdentity = map[string]any{"oversized": strings.Repeat("x", 1<<20)} },
		func(v *domain.BuildRun) { v.SourceIdentity = map[string]any{"invalid": make(chan int)} },
		func(v *domain.BuildRun) { v.Outputs = []domain.BuildOutput{{Digest: strings.Repeat("x", 1<<20)}} },
	} {
		v := original
		mutate(&v)
		tx.state.BuildRuns[v.ID] = v
		if out, err := b.GetBuildPoint(t.Context(), "tenant", v.ID); !errors.Is(err, releasequery.ErrInvalidProjection) || !reflect.DeepEqual(out, releasequery.BuildPoint{}) {
			t.Fatal("corrupt build returned partial data", out, err)
		}
	}
	tx.state.BuildRuns[original.ID] = original
	originalCandidate := tx.state.ReleaseCandidates["candidate"]
	for _, mutate := range []func(*domain.ReleaseCandidate){
		func(v *domain.ReleaseCandidate) { v.State = "unknown" },
		func(v *domain.ReleaseCandidate) { v.Revision = 0 },
		func(v *domain.ReleaseCandidate) { v.Name = strings.Repeat("x", 65537) },
		func(v *domain.ReleaseCandidate) { v.BuildIDs = make([]string, 4097) },
		func(v *domain.ReleaseCandidate) { v.BuildIDs = []string{strings.Repeat("x", 1025)} },
	} {
		v := originalCandidate
		mutate(&v)
		tx.state.ReleaseCandidates[v.ID] = v
		if out, err := c.GetReleaseCandidatePoint(t.Context(), "tenant", v.ID); !errors.Is(err, releasequery.ErrInvalidProjection) || !reflect.DeepEqual(out, releasequery.ReleaseCandidatePoint{}) {
			t.Fatal("corrupt candidate returned partial data", out, err)
		}
	}
	tx.state.ReleaseCandidates[originalCandidate.ID] = originalCandidate
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var absent context.Context
	for _, check := range []struct {
		ctx  context.Context
		want error
	}{{ctx, context.Canceled}, {absent, releasequery.ErrValidation}} {
		if v, err := b.GetBuildPoint(check.ctx, "tenant", "build"); !errors.Is(err, check.want) || !reflect.DeepEqual(v, releasequery.BuildPoint{}) {
			t.Fatal("invalid context returned build", v, err)
		}
		if v, err := c.GetReleaseCandidatePoint(check.ctx, "tenant", "candidate"); !errors.Is(err, check.want) || !reflect.DeepEqual(v, releasequery.ReleaseCandidatePoint{}) {
			t.Fatal("invalid context returned candidate", v, err)
		}
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.GetBuildPoint(t.Context(), "tenant", "build"); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction returned build", err)
	}
	if _, err := c.GetReleaseCandidatePoint(t.Context(), "tenant", "candidate"); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction returned candidate", err)
	}
}

func TestMemoryCandidatePagesFilterCurrentParentsGrantsAndKeysetBeforeMetadata(t *testing.T) {
	tx, _, c := memoryBuildCandidateQueryFixture(t)
	original := tx.state.ReleaseCandidates["candidate"]
	tx.state.ReleaseCandidates = map[string]domain.ReleaseCandidate{}
	for _, id := range []string{"a", "b", "c"} {
		v := original
		v.ID = id
		tx.state.ReleaseCandidates[id] = v
	}
	bad := original
	bad.ID, bad.TenantID, bad.Name = "foreign", "foreign", strings.Repeat("x", 65537)
	tx.state.ReleaseCandidates[bad.ID] = bad
	bad.ID, bad.TenantID, bad.ReleaseID = "dangling", "tenant", "missing"
	tx.state.ReleaseCandidates[bad.ID] = bad
	req := releasequery.ReleaseCandidatePageRequest{TenantID: "tenant", TenantWide: true, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	page, err := c.PageReleaseCandidates(t.Context(), req)
	want, _ := releaseCandidateToReleaseContext(tx.state.ReleaseCandidates["a"])
	if err != nil || len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0], releasequery.ReleaseCandidatePoint{Candidate: want, ProductID: "tenant-product"}) || page.Next == nil || page.Next.ID != "a" {
		t.Fatal("candidate first page fields/cursor changed", page, err)
	}
	req.After = page.Next
	page, err = c.PageReleaseCandidates(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].Candidate.ID != "b" || page.Next == nil || page.Next.ID != "b" {
		t.Fatal("candidate cursor did not advance", page, err)
	}
	req.After, req.Page.Sort, req.Page.Direction = nil, appquery.SortCreatedAt, appquery.Descending
	page, err = c.PageReleaseCandidates(t.Context(), req)
	if err != nil || page.Items[0].Candidate.ID != "c" || page.Next == nil || page.Next.Value != fixedNow().Format(time.RFC3339Nano) {
		t.Fatal("candidate created-at direction/tie-break changed", page, err)
	}
	bad = tx.state.ReleaseCandidates["a"]
	bad.Name = strings.Repeat("x", 65537)
	tx.state.ReleaseCandidates[bad.ID] = bad
	if _, err := c.PageReleaseCandidates(t.Context(), req); err != nil {
		t.Fatal("page decoded unselected metadata", err)
	}
	tx.state.Products["ungranted-product"] = domain.Product{ID: "ungranted-product", TenantID: "tenant"}
	tx.state.Releases["ungranted-release"] = domain.Release{ID: "ungranted-release", TenantID: "tenant", ProductID: "ungranted-product"}
	bad.ID, bad.ReleaseID = "z-ungranted", "ungranted-release"
	tx.state.ReleaseCandidates[bad.ID] = bad
	req.TenantWide, req.AllowedReleaseIDs, req.ReleaseID = false, []string{"foreign-release"}, "tenant-release"
	if page, err := c.PageReleaseCandidates(t.Context(), req); err != nil || len(page.Items) != 0 || page.Next != nil {
		t.Fatal("page ignored release grant/filter", page, err)
	}
	req.AllowedReleaseIDs, req.ReleaseID = []string{"tenant-release"}, "foreign-release"
	if page, err := c.PageReleaseCandidates(t.Context(), req); err != nil || len(page.Items) != 0 {
		t.Fatal("page ignored release filter", page, err)
	}
	req.AllowedReleaseIDs, req.AllowedProductIDs, req.ReleaseID = nil, []string{"tenant-product"}, ""
	page, err = c.PageReleaseCandidates(t.Context(), req)
	if err != nil || len(page.Items) != 1 || page.Items[0].Candidate.ID != "c" {
		t.Fatal("product grant failed current parent filter", page, err)
	}
	req.Page.Direction = appquery.Ascending
	if v, err := c.PageReleaseCandidates(t.Context(), req); !errors.Is(err, releasequery.ErrInvalidProjection) || !reflect.DeepEqual(v, appquery.Result[releasequery.ReleaseCandidatePoint]{}) {
		t.Fatal("corrupt selected candidate produced partial page", v, err)
	}
	req.TenantWide = true
	if _, err := c.PageReleaseCandidates(t.Context(), req); !errors.Is(err, releasequery.ErrValidation) {
		t.Fatal("contradictory grant page accepted", err)
	}
	req.TenantWide, req.AllowedProductIDs = false, nil
	if _, err := c.PageReleaseCandidates(t.Context(), req); !errors.Is(err, releasequery.ErrValidation) {
		t.Fatal("unscoped page accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	req.TenantWide = true
	if v, err := c.PageReleaseCandidates(ctx, req); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, appquery.Result[releasequery.ReleaseCandidatePoint]{}) {
		t.Fatal("cancelled page returned data", v, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v, err := c.PageReleaseCandidates(t.Context(), req); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, appquery.Result[releasequery.ReleaseCandidatePoint]{}) {
		t.Fatal("closed transaction returned candidate page", v, err)
	}
}
