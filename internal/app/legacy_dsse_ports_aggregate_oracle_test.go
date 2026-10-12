package app

import (
	"errors"
	"reflect"
)

func validateLedgerDSSEPorts(cfg Config) error {
	for _, port := range []any{cfg.BuildAttestationParser, cfg.DSSEPolicyVerifier} {
		if port == nil {
			return errors.New("build-attestation parser and DSSE policy verifier ports are required")
		}
		value := reflect.ValueOf(port)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if value.IsNil() {
				return errors.New("build-attestation parser and DSSE policy verifier ports are required")
			}
		}
	}
	return nil
}
