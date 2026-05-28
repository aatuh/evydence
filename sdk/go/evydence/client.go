package evydence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

type CreateSSOProviderRequest struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Issuer      string            `json:"issuer"`
	ClientID    string            `json:"client_id"`
	GroupsClaim string            `json:"groups_claim,omitempty"`
	RoleMapping map[string]string `json:"role_mapping,omitempty"`
	JWKS        map[string]any    `json:"jwks,omitempty"`
}

type VerifyProviderIdentityRequest struct {
	ProviderType string `json:"provider_type"`
	ProviderID   string `json:"provider_id"`
	Subject      string `json:"subject"`
	IDToken      string `json:"id_token,omitempty"`
}

func (c Client) Post(ctx context.Context, path, idempotencyKey string, payload any, out any) error {
	if !strings.HasPrefix(path, "/v1/") || strings.TrimSpace(idempotencyKey) == "" {
		return fmt.Errorf("evydence: invalid path or idempotency key")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.APIKey))
	req.Header.Set("Idempotency-Key", idempotencyKey)
	req.Header.Set("Content-Type", "application/json")
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("evydence: request failed with status %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(responseBody, out)
}

func (c Client) CreateSSOProvider(ctx context.Context, idempotencyKey string, payload CreateSSOProviderRequest, out any) error {
	return c.Post(ctx, "/v1/sso/providers", idempotencyKey, payload, out)
}

func (c Client) VerifyProviderIdentity(ctx context.Context, idempotencyKey string, payload VerifyProviderIdentityRequest, out any) error {
	return c.Post(ctx, "/v1/provider-verifications", idempotencyKey, payload, out)
}
