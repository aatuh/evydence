package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"golang.org/x/oauth2"

	"github.com/aatuh/evydence/internal/adapters/identity/httpvalidator"
	"github.com/aatuh/evydence/internal/adapters/signing/awskms"
	"github.com/aatuh/evydence/internal/adapters/signing/azurekeyvault"
	"github.com/aatuh/evydence/internal/adapters/signing/gcpkms"
	signinggateway "github.com/aatuh/evydence/internal/adapters/signing/httpgateway"
	transparencygateway "github.com/aatuh/evydence/internal/adapters/transparency/httpgateway"
)

type providerBorrowedTransport struct{ closes atomic.Int32 }

func (*providerBorrowedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected provider network request")
}
func (t *providerBorrowedTransport) CloseIdleConnections() { t.closes.Add(1) }

type providerBorrowedCredential struct{}

func (providerBorrowedCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fixture", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestConstructedProvidersPreserveBorrowedCustomTransports(t *testing.T) {
	for _, tc := range []struct {
		name   string
		create func(*http.Client) (io.Closer, error)
	}{
		{"identity-gateway", func(c *http.Client) (io.Closer, error) {
			return httpvalidator.New(httpvalidator.Config{Endpoint: "https://provider.example.test", Client: c})
		}},
		{"transparency-gateway", func(c *http.Client) (io.Closer, error) {
			return transparencygateway.New(transparencygateway.Config{Endpoint: "https://provider.example.test", Client: c})
		}},
		{"signing-gateway", func(c *http.Client) (io.Closer, error) {
			return signinggateway.New(signinggateway.Config{Endpoint: "https://provider.example.test", Client: c, VerificationPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))})
		}},
		{"gcp-kms", func(c *http.Client) (io.Closer, error) {
			return gcpkms.NewWithTokenSource(gcpkms.Config{Client: c, TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fixture"})})
		}},
		{"azure-kms", func(c *http.Client) (io.Closer, error) {
			return azurekeyvault.NewWithCredential(azurekeyvault.Config{VaultURL: "https://vault.example.test", Client: c, Credential: providerBorrowedCredential{}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &providerBorrowedTransport{}
			client := &http.Client{Transport: transport, Timeout: 7 * time.Second}
			provider, err := tc.create(client)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err = provider.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if transport.closes.Load() != 0 || client.Timeout != 7*time.Second {
				t.Fatal("provider mutated or closed caller-owned client")
			}
		})
	}
}

type providerBorrowedKMS struct{ closes atomic.Int32 }

func (*providerBorrowedKMS) Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error) {
	return nil, errors.New("unexpected sign")
}
func (*providerBorrowedKMS) Verify(context.Context, *kms.VerifyInput, ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	return nil, errors.New("unexpected verify")
}
func (c *providerBorrowedKMS) Close() error { c.closes.Add(1); return nil }
func TestConstructedAWSProviderRetainsBorrowedSDKClient(t *testing.T) {
	client := &providerBorrowedKMS{}
	provider, err := awskms.NewWithClient(client, awskms.Config{KeyID: "alias/fixture"})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = provider.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if client.closes.Load() != 0 {
		t.Fatal("AWS adapter closed borrowed SDK client")
	}
}
