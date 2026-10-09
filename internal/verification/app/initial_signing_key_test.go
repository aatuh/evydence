package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
)

type initialSigningWriter struct {
	material []byte
	tenant   string
	err      error
}

type initialSigningFactoryFunc func(context.Context, string, string, int, time.Time) (PreparedSigningKey, error)

func (f initialSigningFactoryFunc) GenerateSigningKey(ctx context.Context, tenant, provider string, version int, now time.Time) (PreparedSigningKey, error) {
	return f(ctx, tenant, provider, version, now)
}

func TestInitialSigningKeyCommandsValidateBeforeGeneratingAndClearFactoryMaterial(t *testing.T) {
	for _, tc := range []struct {
		name                string
		fail, foreign, stop bool
	}{{name: "success"}, {name: "factory failure", fail: true}, {name: "foreign preparation", foreign: true}, {name: "canceled after generation", stop: true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var factoryMaterial []byte
			factoryCalls := 0
			factory := initialSigningFactoryFunc(func(ctx context.Context, tenant, provider string, version int, now time.Time) (PreparedSigningKey, error) {
				factoryCalls++
				p, err := (verificationTestKeyFactory{}).GenerateSigningKey(ctx, tenant, provider, version, now)
				factoryMaterial = p.PrivateMaterial
				if tc.foreign {
					p.Key.TenantID = "foreign"
				}
				if tc.stop {
					cancel()
				}
				if tc.fail {
					err = errors.New("factory failure")
				}
				return p, err
			})
			commands, err := NewInitialSigningKeyCommands(InitialSigningKeyConfig{KeyFactory: factory, Clock: application.ClockFunc(verificationTestNow)})
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range []string{"", "tenant\x00", string([]byte{0xff}), strings.Repeat(" ", 1024) + "a"} {
				if _, err := commands.PrepareInitialSigningKey(ctx, bad); !errors.Is(err, ErrValidation) || factoryCalls != 0 {
					t.Fatal("malformed tenant reached signing factory", err)
				}
			}
			p, err := commands.PrepareInitialSigningKey(ctx, "ten_1")
			failed := tc.fail || tc.foreign || tc.stop
			if (err != nil) != failed || factoryCalls != 1 || !reflect.DeepEqual(factoryMaterial, make([]byte, len(factoryMaterial))) {
				t.Fatal("factory source material was retained or preparation changed", err)
			}
			if failed && !reflect.DeepEqual(p, PreparedSigningKey{}) {
				t.Fatal("failed preparation returned signing material")
			}
			if !failed && string(p.PrivateMaterial) != "private-material" {
				t.Fatal("successful preparation aliases cleared factory source")
			}
			clear(p.PrivateMaterial)
		})
	}
}

func (w *initialSigningWriter) InsertSigningKey(_ context.Context, p PreparedSigningKey) error {
	w.material, w.tenant = p.PrivateMaterial, p.Key.TenantID
	return w.err
}

func TestInitialSigningKeyCommandsOwnOnlySigningPreparationAndWrite(t *testing.T) {
	config := InitialSigningKeyConfig{KeyFactory: verificationTestKeyFactory{}, Clock: application.ClockFunc(verificationTestNow)}
	commands, err := NewInitialSigningKeyCommands(config)
	if err != nil {
		t.Fatal(err)
	}
	p, err := commands.PrepareInitialSigningKey(t.Context(), "ten_1")
	if err != nil || p.Key.TenantID != "ten_1" || p.Key.Version != 1 {
		t.Fatal("focused signing preparation failed", err)
	}
	for _, failure := range []error{nil, errors.New("write failed")} {
		writer := &initialSigningWriter{err: failure}
		if err := commands.CommitInitialSigningKey(t.Context(), writer, "ten_1", p); !errors.Is(err, failure) || writer.tenant != "ten_1" {
			t.Fatal("signing commit changed its boundary", err)
		}
		if !reflect.DeepEqual(writer.material, make([]byte, len(p.PrivateMaterial))) || string(p.PrivateMaterial) != "private-material" {
			t.Fatal("transient signing material was not cleared, or caller material was aliased")
		}
	}
	writer := &initialSigningWriter{}
	if err := commands.CommitInitialSigningKey(t.Context(), writer, "foreign", p); !errors.Is(err, ErrValidation) || writer.tenant != "" {
		t.Fatal("foreign prepared key reached signing repository", err)
	}
	for _, alter := range []func(*InitialSigningKeyConfig){func(c *InitialSigningKeyConfig) { c.Clock = nil }, func(c *InitialSigningKeyConfig) { c.KeyFactory = nil }} {
		bad := config
		alter(&bad)
		if _, err := NewInitialSigningKeyCommands(bad); !errors.Is(err, ErrValidation) {
			t.Fatal("missing signing dependency accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if p, err := commands.PrepareInitialSigningKey(ctx, "ten_1"); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(p, PreparedSigningKey{}) {
		t.Fatal("canceled signing preparation returned private material")
	}
}
