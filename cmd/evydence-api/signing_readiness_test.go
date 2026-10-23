package main

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

type presenceOnlySigner struct{ signCalls int }

func (s *presenceOnlySigner) Sign(context.Context, app.SigningRequest) (app.SigningResult, error) {
	s.signCalls++
	return app.SigningResult{}, nil
}

type readinessSigner struct {
	presenceOnlySigner
	check func(context.Context) error
}

func (s *readinessSigner) CheckReadiness(ctx context.Context) error { return s.check(ctx) }

func TestSigningReadinessRequiresOperationalProbeAndRecovers(t *testing.T) {
	presence := &presenceOnlySigner{}
	if err := signingConfigurationReadiness(presence)(t.Context()); err == nil || presence.signCalls != 0 {
		t.Fatal("mere executor presence was treated as operational health")
	}
	unavailable := false
	checks := 0
	signer := &readinessSigner{check: func(ctx context.Context) error {
		checks++
		if ctx != t.Context() {
			t.Fatal("probe context was replaced")
		}
		if unavailable {
			return errors.New("provider temporarily unavailable")
		}
		return nil
	}}
	probe := signingConfigurationReadiness(signer)
	if err := probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	unavailable = true
	if err := probe(t.Context()); err == nil {
		t.Fatal("dependency outage was ignored")
	}
	unavailable = false
	if err := probe(t.Context()); err != nil {
		t.Fatal("restored dependency did not recover", err)
	}
	if checks != 3 || signer.signCalls != 0 {
		t.Fatalf("probe checks=%d sign calls=%d", checks, signer.signCalls)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := probe(canceled); !errors.Is(err, context.Canceled) || checks != 3 {
		t.Fatal("canceled probe performed provider I/O", err)
	}
}
