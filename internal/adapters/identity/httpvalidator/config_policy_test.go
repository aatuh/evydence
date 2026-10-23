package httpvalidator

import (
	"testing"
)

func TestConstructorUsesHTTPPolicyLoopbackForms(t *testing.T) {
	for _, endpoint := range []string{"http://LOCALHOST:1/endpoint", "http://localhost.:1/endpoint", "http://[::ffff:127.0.0.1]:1/endpoint"} {
		client, err := New(Config{
			Endpoint:                  endpoint,
			AllowInsecureForLocalhost: true,
		})
		if err != nil {
			t.Fatal("constructor rejected a loopback form allowed by the HTTP policy", err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConstructorRejectsHTTPPrefixImpersonation(t *testing.T) {
	client, err := New(Config{Endpoint: "http://127.evil.invalid/endpoint", AllowInsecureForLocalhost: true})
	if client != nil {
		_ = client.Close()
	}
	if err == nil || client != nil {
		t.Fatal("a hostname prefix impersonated literal loopback")
	}
}
