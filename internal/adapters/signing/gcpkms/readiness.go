package gcpkms

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/aatuh/evydence/internal/app"
)

const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

var errReadiness = errors.New("GCP KMS signing dependency is unavailable")

// CheckReadiness reads the configured default key version, without signing.
// A separate, context-aware credential source prevents signing's legacy token
// refresh/cache mutex from extending a probe beyond its own deadline.
func (e *Executor) CheckReadiness(ctx context.Context) error {
	if e == nil || e.client == nil || e.readinessToken == nil || ctx == nil {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validKeyName(e.keyName) {
		return errReadiness
	}
	timeout := e.client.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	token, err := e.readinessToken(callCtx)
	if callCtx.Err() != nil {
		return callCtx.Err()
	}
	if err != nil || token == nil || !token.Valid() {
		return errReadiness
	}
	request, err := http.NewRequestWithContext(callCtx, http.MethodGet, e.endpoint+"/v1/"+e.keyName, nil)
	if err != nil {
		return errReadiness
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	response, err := e.client.Do(request)
	if err != nil {
		if callCtx.Err() != nil {
			return callCtx.Err()
		}
		return errReadiness
	}
	defer func() { _ = response.Body.Close() }()
	const maxMetadataBytes = 64 << 10
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataBytes+1))
	if err != nil || len(body) > maxMetadataBytes || response.StatusCode != http.StatusOK {
		return errReadiness
	}
	var version struct {
		Name      string `json:"name"`
		State     string `json:"state"`
		Algorithm string `json:"algorithm"`
	}
	if json.Unmarshal(body, &version) != nil || version.Name != e.keyName || version.State != "ENABLED" || !slices.Contains([]string{
		"EC_SIGN_P256_SHA256", "RSA_SIGN_PSS_2048_SHA256", "RSA_SIGN_PSS_3072_SHA256", "RSA_SIGN_PSS_4096_SHA256",
		"RSA_SIGN_PKCS1_2048_SHA256", "RSA_SIGN_PKCS1_3072_SHA256", "RSA_SIGN_PKCS1_4096_SHA256",
	}, version.Algorithm) {
		return errReadiness
	}
	return callCtx.Err()
}

// ADC JSON is operator-controlled material already parsed by Google's SDK at
// startup. Reconstruct only the health source with each refresh context; the
// supported credential-type validation and exchange remain in the pinned SDK.
// Metadata-backed ADC uses that SDK's context-aware metadata client directly.
func newReadinessTokenSource(credentialJSON []byte, client *http.Client) func(context.Context) (*oauth2.Token, error) {
	credentialJSON = append([]byte(nil), credentialJSON...)
	ownedClient := *client
	base := ownedClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	ownedClient.Transport = readinessTokenTransport{base: base}
	metadataClient := metadata.NewClient(&ownedClient)
	var mu sync.Mutex
	var cached oauth2.Token
	return func(ctx context.Context) (*oauth2.Token, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mu.Lock()
		current := cached
		mu.Unlock()
		if current.Valid() {
			return &current, nil
		}
		var token *oauth2.Token
		if len(credentialJSON) != 0 {
			var declared struct {
				Type google.CredentialsType `json:"type"`
			}
			if json.Unmarshal(credentialJSON, &declared) != nil {
				return nil, errReadiness
			}
			credentialCtx := context.WithValue(ctx, oauth2.HTTPClient, &ownedClient)
			credentials, err := google.CredentialsFromJSONWithTypeAndParams(credentialCtx, credentialJSON, declared.Type, google.CredentialsParams{Scopes: []string{cloudPlatformScope}})
			if err != nil {
				return nil, errReadiness
			}
			token, err = credentials.TokenSource.Token()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err != nil {
				return nil, errReadiness
			}
		} else {
			body, err := metadataClient.GetWithContext(ctx, "instance/service-accounts/default/token?scopes="+url.QueryEscape(cloudPlatformScope))
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			token = &oauth2.Token{}
			if err != nil || len(body) > 64<<10 || json.Unmarshal([]byte(body), token) != nil || token.ExpiresIn <= 0 || token.ExpiresIn > 86400 {
				return nil, errReadiness
			}
			token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
		}
		if token == nil || strings.TrimSpace(token.AccessToken) == "" || !token.Valid() {
			return nil, errReadiness
		}
		if !token.Expiry.IsZero() {
			mu.Lock()
			cached = *token
			mu.Unlock()
		}
		copy := *token
		return &copy, nil
	}
}

// The provider owns the base transport. This view only bounds SDK token-body
// allocation; it never closes or mutates the shared pool or borrowed client.
type readinessTokenTransport struct{ base http.RoundTripper }

func (t readinessTokenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err == nil && response != nil && response.Body != nil {
		response.Body = struct {
			io.Reader
			io.Closer
		}{Reader: io.LimitReader(response.Body, (64<<10)+1), Closer: response.Body}
	}
	return response, err
}
