package httpgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const defaultTimeout = 10 * time.Second

type Config struct {
	Endpoint                  string
	BearerToken               string
	Timeout                   time.Duration
	AllowInsecureForLocalhost bool
	Client                    *http.Client
}

type Executor struct {
	endpoint    string
	bearerToken string
	client      *http.Client
}

type signRequest struct {
	TenantID     string `json:"tenant_id"`
	ProviderID   string `json:"provider_id"`
	ProviderType string `json:"provider_type"`
	KeyRef       string `json:"key_ref"`
	SubjectType  string `json:"subject_type"`
	SubjectID    string `json:"subject_id"`
	PayloadHash  string `json:"payload_hash"`
}

type signResponse struct {
	Signature string `json:"signature"`
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
}

func New(cfg Config) (*Executor, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, app.ErrValidation
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, app.ErrValidation
	}
	if parsed.Scheme != "https" && (!cfg.AllowInsecureForLocalhost || parsed.Scheme != "http" || !localhostHost(parsed.Hostname())) {
		return nil, errors.New("signing gateway endpoint must use https")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &Executor{endpoint: endpoint, bearerToken: strings.TrimSpace(cfg.BearerToken), client: client}, nil
}

func (e *Executor) Sign(ctx context.Context, request app.SigningRequest) (app.SigningResult, error) {
	if e == nil || e.client == nil {
		return app.SigningResult{}, app.ErrValidation
	}
	body, err := json.Marshal(signRequest{
		TenantID:     request.TenantID,
		ProviderID:   request.ProviderID,
		ProviderType: request.ProviderType,
		KeyRef:       request.KeyRef,
		SubjectType:  request.SubjectType,
		SubjectID:    request.SubjectID,
		PayloadHash:  request.PayloadHash,
	})
	if err != nil {
		return app.SigningResult{}, fmt.Errorf("encode signing request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return app.SigningResult{}, fmt.Errorf("create signing request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if e.bearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.bearerToken)
	}
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return app.SigningResult{}, errors.New("execute signing request")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return app.SigningResult{}, fmt.Errorf("signing gateway returned status %d", resp.StatusCode)
	}
	var decoded signResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return app.SigningResult{}, errors.New("decode signing response")
	}
	decoded.Signature = strings.TrimSpace(decoded.Signature)
	decoded.KeyID = strings.TrimSpace(decoded.KeyID)
	decoded.Algorithm = strings.TrimSpace(decoded.Algorithm)
	if decoded.Signature == "" || len(decoded.Signature) > 32768 {
		return app.SigningResult{}, app.ErrValidation
	}
	return app.SigningResult{
		Signature: decoded.Signature,
		KeyID:     decoded.KeyID,
		Algorithm: decoded.Algorithm,
		Checks: []domain.VerifyCheck{
			{Name: "signing_gateway_response", Result: "passed", Detail: "External signing gateway returned a signature over the submitted payload hash."},
		},
	}, nil
}

func localhostHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
