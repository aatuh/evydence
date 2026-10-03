package wiring

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestDurableCommandExecutorRequiresFactoryAndBothCallbacks(t *testing.T) {
	if _, err := BuildDurableCommandExecutor(nil); err == nil {
		t.Fatal("nil transaction factory accepted")
	}
	executor, err := BuildDurableCommandExecutor(app.NewMemoryUnitOfWorkFactory())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		authorize func(context.Context) error
		run       func(context.Context) (int, any, error)
	}{
		{nil, func(context.Context) (int, any, error) {
			t.Fatal("missing authorization executed command")
			return 0, nil, nil
		}},
		{func(context.Context) error { t.Fatal("missing command began authorization"); return nil }, nil},
	} {
		status, response, err := executor.WithBody(t.Context(), domain.Actor{}, "POST", "/test", "key", nil, test.authorize, test.run)
		if !errors.Is(err, app.ErrValidation) || status != 0 || response != nil {
			t.Fatal("incomplete durable command exposed a result", status, response, err)
		}
	}
}
