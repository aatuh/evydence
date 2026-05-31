package httpvalidator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const (
	defaultTimeout = 10 * time.Second
	maxBodyBytes   = 1 << 20
)

type Config struct {
	Endpoint                  string
	BearerToken               string
	Timeout                   time.Duration
	AllowInsecureForLocalhost bool
	Client                    *http.Client
}

type Validator struct {
	endpoint    string
	bearerToken string
	client      *http.Client
}

type validationRequest struct {
	TenantID           string `json:"tenant_id"`
	ProviderID         string `json:"provider_id"`
	ProviderType       string `json:"provider_type"`
	Issuer             string `json:"issuer,omitempty"`
	Subject            string `json:"subject"`
	GroupsClaim        string `json:"groups_claim,omitempty"`
	AccessToken        string `json:"access_token,omitempty"`
	AccessTokenPresent bool   `json:"access_token_present"`
}

type validationResponse struct {
	Subject     string               `json:"subject,omitempty"`
	Groups      []string             `json:"groups,omitempty"`
	Checks      []domain.VerifyCheck `json:"checks,omitempty"`
	Limitations []string             `json:"limitations,omitempty"`
}

func New(cfg Config) (*Validator, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, app.ErrValidation
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, app.ErrValidation
	}
	if parsed.Scheme != "https" && (!cfg.AllowInsecureForLocalhost || parsed.Scheme != "http" || !localhostHost(parsed.Hostname())) {
		return nil, errors.New("provider validation gateway endpoint must use https")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &Validator{endpoint: endpoint, bearerToken: strings.TrimSpace(cfg.BearerToken), client: client}, nil
}

func (v *Validator) ValidateProviderIdentity(ctx context.Context, req app.ProviderIdentityValidationRequest) (app.ProviderIdentityValidationResult, error) {
	if v == nil || v.client == nil {
		return app.ProviderIdentityValidationResult{}, app.ErrValidation
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		return app.ProviderIdentityValidationResult{}, app.ErrValidation
	}
	accessToken := strings.TrimSpace(req.AccessToken)
	if len(accessToken) > 16*1024 {
		return app.ProviderIdentityValidationResult{}, app.ErrValidation
	}
	body, err := json.Marshal(validationRequest{
		TenantID:           strings.TrimSpace(req.TenantID),
		ProviderID:         strings.TrimSpace(req.ProviderID),
		ProviderType:       strings.TrimSpace(req.ProviderType),
		Issuer:             strings.TrimSpace(req.Issuer),
		Subject:            subject,
		GroupsClaim:        strings.TrimSpace(req.GroupsClaim),
		AccessToken:        accessToken,
		AccessTokenPresent: accessToken != "",
	})
	if err != nil {
		return app.ProviderIdentityValidationResult{}, app.ErrValidation
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, bytes.NewReader(body))
	if err != nil {
		return app.ProviderIdentityValidationResult{}, app.ErrValidation
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	if v.bearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+v.bearerToken)
	}
	resp, err := v.client.Do(httpReq)
	if err != nil {
		return app.ProviderIdentityValidationResult{}, errors.New("provider validation gateway request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return failed("provider_validation_gateway_status"), app.ErrVerificationFailed
	}
	var decoded validationResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return failed("provider_validation_gateway_response"), app.ErrVerificationFailed
	}
	if decoder.InputOffset() > maxBodyBytes {
		return failed("provider_validation_gateway_response_size"), app.ErrVerificationFailed
	}
	decoded.Subject = strings.TrimSpace(decoded.Subject)
	if decoded.Subject != "" && decoded.Subject != subject {
		return app.ProviderIdentityValidationResult{
			Checks:      append(safeChecks(decoded.Checks), domain.VerifyCheck{Name: "provider_validation_gateway_subject", Result: "failed"}),
			Groups:      safeGroups(decoded.Groups),
			Limitations: safeLimitations(decoded.Limitations),
		}, app.ErrVerificationFailed
	}
	checks := safeChecks(decoded.Checks)
	checks = append([]domain.VerifyCheck{{Name: "provider_validation_gateway", Result: "passed"}}, checks...)
	if decoded.Subject != "" {
		checks = append(checks, domain.VerifyCheck{Name: "provider_validation_gateway_subject", Result: "passed"})
	}
	limitations := safeLimitations(decoded.Limitations)
	if len(limitations) == 0 {
		limitations = []string{"Provider validation gateway returned non-secret identity checks; Evydence does not store supplied access tokens or synchronize provider groups permanently."}
	}
	return app.ProviderIdentityValidationResult{Checks: checks, Groups: safeGroups(decoded.Groups), Limitations: limitations}, nil
}

func failed(check string) app.ProviderIdentityValidationResult {
	return app.ProviderIdentityValidationResult{
		Checks:      []domain.VerifyCheck{{Name: check, Result: "failed"}},
		Limitations: []string{"Provider validation gateway failed without storing supplied access tokens or raw provider responses."},
	}
}

func safeChecks(in []domain.VerifyCheck) []domain.VerifyCheck {
	out := make([]domain.VerifyCheck, 0, len(in))
	for _, check := range in {
		name := strings.TrimSpace(check.Name)
		result := strings.TrimSpace(check.Result)
		detail := strings.TrimSpace(check.Detail)
		if name == "" || result == "" || len(name) > 128 || len(result) > 32 || len(detail) > 1024 {
			continue
		}
		out = append(out, domain.VerifyCheck{Name: name, Result: result, Detail: detail})
		if len(out) >= 32 {
			break
		}
	}
	return out
}

func safeGroups(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, group := range in {
		group = strings.TrimSpace(group)
		if group == "" || len(group) > 256 {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		out = append(out, group)
		if len(out) >= 128 {
			break
		}
	}
	return out
}

func safeLimitations(in []string) []string {
	out := make([]string, 0, len(in))
	for _, limitation := range in {
		limitation = strings.TrimSpace(limitation)
		if limitation == "" || len(limitation) > 1024 {
			continue
		}
		out = append(out, limitation)
		if len(out) >= 16 {
			break
		}
	}
	return out
}

func localhostHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
