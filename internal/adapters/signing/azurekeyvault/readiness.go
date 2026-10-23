package azurekeyvault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/aatuh/evydence/internal/app"
)

var errReadiness = errors.New("azure key vault signing dependency is unavailable")

// CheckReadiness reads the configured default key's public metadata. It does
// not sign a test payload or establish permission to use every tenant's key.
func (e *Executor) CheckReadiness(ctx context.Context) error {
	if e == nil || e.client == nil || e.credential == nil || ctx == nil {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	vault, name, version, err := e.resolveKey("")
	if err != nil {
		return errReadiness
	}
	timeout := e.client.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	token, err := e.credential.GetToken(callCtx, policy.TokenRequestOptions{Scopes: []string{"https://vault.azure.net/.default"}})
	if callCtx.Err() != nil {
		return callCtx.Err()
	}
	if err != nil || strings.TrimSpace(token.Token) == "" || (!token.ExpiresOn.IsZero() && !token.ExpiresOn.After(time.Now())) {
		return errReadiness
	}
	keyURL := vault + "/keys/" + url.PathEscape(name) + "/" + url.PathEscape(version)
	request, err := http.NewRequestWithContext(callCtx, http.MethodGet, keyURL+"?api-version="+url.QueryEscape(e.apiVersion), nil)
	if err != nil {
		return errReadiness
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token.Token)
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
	var metadata struct {
		Key struct {
			ID         string   `json:"kid"`
			Type       string   `json:"kty"`
			Curve      string   `json:"crv"`
			Operations []string `json:"key_ops"`
			X          string   `json:"x"`
			Y          string   `json:"y"`
		} `json:"key"`
		Attributes *struct {
			Enabled   bool   `json:"enabled"`
			Expires   *int64 `json:"exp"`
			NotBefore *int64 `json:"nbf"`
		} `json:"attributes"`
	}
	if json.Unmarshal(body, &metadata) != nil || metadata.Attributes == nil || !metadata.Attributes.Enabled || metadata.Key.ID != keyURL || metadata.Key.Type != "EC" || metadata.Key.Curve != "P-256" || !slices.Contains(metadata.Key.Operations, "sign") {
		return errReadiness
	}
	now := time.Now().Unix()
	if (metadata.Attributes.Expires != nil && *metadata.Attributes.Expires <= now) || (metadata.Attributes.NotBefore != nil && *metadata.Attributes.NotBefore > now) {
		return errReadiness
	}
	x, xErr := base64.RawURLEncoding.DecodeString(metadata.Key.X)
	y, yErr := base64.RawURLEncoding.DecodeString(metadata.Key.Y)
	if xErr != nil || yErr != nil || len(x) != 32 || len(y) != 32 {
		return errReadiness
	}
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, append(x, y...)...)); err != nil {
		return errReadiness
	}
	return callCtx.Err()
}
