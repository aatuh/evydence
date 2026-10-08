package httpapi

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type catalogNativeRepository interface {
	ReadCatalogProduct(context.Context, string, string) (releasedomain.Product, error)
	ReadCatalogProject(context.Context, string, string) (releasedomain.Project, error)
	ReadCatalogRelease(context.Context, string, string) (releasedomain.Release, error)
	PageProducts(context.Context, releasequery.ProductPageRequest) (appquery.Result[releasedomain.Product], error)
}

func (f catalogNativeFixtureReader) readCandidate(ctx context.Context, run func(context.Context, releasequery.ReleaseCandidateReader) error) error {
	if ctx == nil {
		return releasequery.ErrValidation
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.ReleaseCatalog.(releasequery.ReleaseCandidateReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, reader)
	})
}

func (f catalogNativeFixtureReader) GetBuildPoint(ctx context.Context, tenant, id string) (releasequery.BuildPoint, error) {
	if ctx == nil {
		return releasequery.BuildPoint{}, releasequery.ErrValidation
	}
	var out releasequery.BuildPoint
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Builds.(releasequery.BuildPointReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.GetBuildPoint(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasequery.BuildPoint{}, err
	}
	return out, nil
}

func (f catalogNativeFixtureReader) GetReleaseCandidatePoint(ctx context.Context, tenant, id string) (releasequery.ReleaseCandidatePoint, error) {
	var out releasequery.ReleaseCandidatePoint
	err := f.readCandidate(ctx, func(ctx context.Context, r releasequery.ReleaseCandidateReader) error {
		var err error
		out, err = r.GetReleaseCandidatePoint(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasequery.ReleaseCandidatePoint{}, err
	}
	return out, nil
}

func (f catalogNativeFixtureReader) PageReleaseCandidates(ctx context.Context, req releasequery.ReleaseCandidatePageRequest) (appquery.Result[releasequery.ReleaseCandidatePoint], error) {
	var out appquery.Result[releasequery.ReleaseCandidatePoint]
	err := f.readCandidate(ctx, func(ctx context.Context, r releasequery.ReleaseCandidateReader) error {
		var err error
		out, err = r.PageReleaseCandidates(ctx, req)
		return err
	})
	if err != nil {
		return appquery.Result[releasequery.ReleaseCandidatePoint]{}, err
	}
	return out, nil
}

type catalogNativeFixtureReader struct{ catalogFixtureCommands }

func catalogQueryTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	return operationsTestServer(t)
}

func (f catalogNativeFixtureReader) read(ctx context.Context, run func(context.Context, catalogNativeRepository) error) error {
	if ctx == nil {
		return releasequery.ErrValidation
	}
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.ReleaseCatalog.(catalogNativeRepository)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, reader)
	})
}
func (f catalogNativeFixtureReader) GetProduct(ctx context.Context, tenant, id string) (releasedomain.Product, error) {
	var out releasedomain.Product
	err := f.read(ctx, func(ctx context.Context, r catalogNativeRepository) error {
		var err error
		out, err = r.ReadCatalogProduct(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Product{}, err
	}
	return out, nil
}
func (f catalogNativeFixtureReader) GetProject(ctx context.Context, tenant, id string) (releasedomain.Project, error) {
	var out releasedomain.Project
	err := f.read(ctx, func(ctx context.Context, r catalogNativeRepository) error {
		var err error
		out, err = r.ReadCatalogProject(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Project{}, err
	}
	return out, nil
}
func (f catalogNativeFixtureReader) GetRelease(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	var out releasedomain.Release
	err := f.read(ctx, func(ctx context.Context, r catalogNativeRepository) error {
		var err error
		out, err = r.ReadCatalogRelease(ctx, tenant, id)
		return err
	})
	if err != nil {
		return releasedomain.Release{}, err
	}
	return out, nil
}
func (f catalogNativeFixtureReader) PageProducts(ctx context.Context, req releasequery.ProductPageRequest) (appquery.Result[releasedomain.Product], error) {
	var out appquery.Result[releasedomain.Product]
	err := f.read(ctx, func(ctx context.Context, r catalogNativeRepository) error {
		var err error
		out, err = r.PageProducts(ctx, req)
		return err
	})
	if err != nil {
		return appquery.Result[releasedomain.Product]{}, err
	}
	return out, nil
}

var (
	_ releasequery.ProductReader          = catalogNativeFixtureReader{}
	_ releasequery.CatalogPointReader     = catalogNativeFixtureReader{}
	_ releasequery.BuildPointReader       = catalogNativeFixtureReader{}
	_ releasequery.ReleaseCandidateReader = catalogNativeFixtureReader{}
)
