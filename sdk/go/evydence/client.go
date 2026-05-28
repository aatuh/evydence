package evydence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

type CreateProductRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type CreateReleaseRequest struct {
	ProductID string `json:"product_id"`
	ProjectID string `json:"project_id,omitempty"`
	Version   string `json:"version"`
}

type RegisterArtifactRequest struct {
	ReleaseID string `json:"release_id,omitempty"`
	Name      string `json:"name"`
	MediaType string `json:"media_type,omitempty"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size,omitempty"`
}

type BuildOutput struct {
	ArtifactID string `json:"artifact_id,omitempty"`
	Digest     string `json:"digest"`
	Name       string `json:"name,omitempty"`
}

type CreateBuildRequest struct {
	ProjectID string         `json:"project_id"`
	ReleaseID string         `json:"release_id"`
	Provider  string         `json:"provider"`
	CommitSHA string         `json:"commit_sha"`
	Status    string         `json:"status"`
	StartedAt string         `json:"started_at"`
	Outputs   []BuildOutput  `json:"outputs,omitempty"`
	GitHub    map[string]any `json:"github,omitempty"`
}

type CreateSSOProviderRequest struct {
	Name                    string            `json:"name"`
	Type                    string            `json:"type"`
	Issuer                  string            `json:"issuer"`
	ClientID                string            `json:"client_id"`
	GroupsClaim             string            `json:"groups_claim,omitempty"`
	RoleMapping             map[string]string `json:"role_mapping,omitempty"`
	JWKS                    map[string]any    `json:"jwks,omitempty"`
	SAMLSigningCertificates []string          `json:"saml_signing_certificates,omitempty"`
}

type VerifyProviderIdentityRequest struct {
	ProviderType  string `json:"provider_type"`
	ProviderID    string `json:"provider_id"`
	Subject       string `json:"subject"`
	IDToken       string `json:"id_token,omitempty"`
	SAMLAssertion string `json:"saml_assertion,omitempty"`
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

func (c Client) Get(ctx context.Context, path string, out any) error {
	if !strings.HasPrefix(path, "/v1/") {
		return fmt.Errorf("evydence: invalid path")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+path, nil)
	if err != nil {
		return err
	}
	if strings.TrimSpace(c.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.APIKey))
	}
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

func (c Client) CreateProduct(ctx context.Context, idempotencyKey string, payload CreateProductRequest, out any) error {
	return c.Post(ctx, "/v1/products", idempotencyKey, payload, out)
}

func (c Client) CreateRelease(ctx context.Context, idempotencyKey string, payload CreateReleaseRequest, out any) error {
	return c.Post(ctx, "/v1/releases", idempotencyKey, payload, out)
}

func (c Client) RegisterArtifact(ctx context.Context, idempotencyKey string, payload RegisterArtifactRequest, out any) error {
	return c.Post(ctx, "/v1/artifacts", idempotencyKey, payload, out)
}

func (c Client) CreateBuild(ctx context.Context, idempotencyKey string, payload CreateBuildRequest, out any) error {
	return c.Post(ctx, "/v1/builds", idempotencyKey, payload, out)
}

func (c Client) Readiness(ctx context.Context, out any) error {
	return c.Get(ctx, "/v1/ready", out)
}

func (c Client) ReleaseReadiness(ctx context.Context, releaseID string, out any) error {
	return c.Get(ctx, "/v1/reports/release-readiness?release_id="+url.QueryEscape(releaseID), out)
}

func (c Client) CreateSSOProvider(ctx context.Context, idempotencyKey string, payload CreateSSOProviderRequest, out any) error {
	return c.Post(ctx, "/v1/sso/providers", idempotencyKey, payload, out)
}

func (c Client) VerifyProviderIdentity(ctx context.Context, idempotencyKey string, payload VerifyProviderIdentityRequest, out any) error {
	return c.Post(ctx, "/v1/provider-verifications", idempotencyKey, payload, out)
}
