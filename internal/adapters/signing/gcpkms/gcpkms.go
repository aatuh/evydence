package gcpkms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const (
	defaultEndpoint = "https://cloudkms.googleapis.com"
	defaultTimeout  = 10 * time.Second
)

type Config struct {
	Endpoint    string
	AccessToken string
	KeyName     string
	Timeout     time.Duration
	Client      *http.Client
}

type Executor struct {
	endpoint    string
	accessToken string
	keyName     string
	client      *http.Client
}

type signRequest struct {
	Digest digestValue `json:"digest"`
}

type digestValue struct {
	SHA256 string `json:"sha256"`
}

type signResponse struct {
	Signature string `json:"signature"`
	Name      string `json:"name,omitempty"`
}

func New(cfg Config) (*Executor, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, app.ErrValidation
	}
	if strings.TrimSpace(cfg.AccessToken) == "" {
		return nil, errors.New("configure GCP KMS access token")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &Executor{
		endpoint:    endpoint,
		accessToken: strings.TrimSpace(cfg.AccessToken),
		keyName:     strings.TrimSpace(cfg.KeyName),
		client:      client,
	}, nil
}

func (e *Executor) Sign(ctx context.Context, req app.SigningRequest) (app.SigningResult, error) {
	if e == nil || e.client == nil {
		return app.SigningResult{}, app.ErrValidation
	}
	if providerType := strings.TrimSpace(req.ProviderType); providerType != "" && providerType != "gcp_kms" {
		return app.SigningResult{}, app.ErrValidation
	}
	digest, err := decodePayloadHash(req.CanonicalPayloadHash)
	if err != nil {
		return app.SigningResult{}, err
	}
	keyName := strings.TrimSpace(req.KeyRef)
	if keyName == "" {
		keyName = e.keyName
	}
	if !validKeyName(keyName) {
		return app.SigningResult{}, app.ErrValidation
	}
	body, err := json.Marshal(signRequest{Digest: digestValue{SHA256: base64.StdEncoding.EncodeToString(digest)}})
	if err != nil {
		return app.SigningResult{}, app.ErrValidation
	}
	signURL := e.endpoint + "/v1/" + strings.TrimLeft(keyName, "/") + ":asymmetricSign"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, signURL, bytes.NewReader(body))
	if err != nil {
		return app.SigningResult{}, app.ErrValidation
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+e.accessToken)
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return app.SigningResult{}, errors.New("execute GCP KMS signing request")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return app.SigningResult{}, fmt.Errorf("gcp KMS signing request returned status %d", resp.StatusCode)
	}
	var decoded signResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return app.SigningResult{}, errors.New("decode GCP KMS signing response")
	}
	decoded.Signature = strings.TrimSpace(decoded.Signature)
	if decoded.Signature == "" || len(decoded.Signature) > 32768 {
		return app.SigningResult{}, app.ErrValidation
	}
	return app.SigningResult{
		Signature:            decoded.Signature,
		KeyID:                firstNonEmpty(strings.TrimSpace(decoded.Name), keyName),
		Algorithm:            "gcp-kms:asymmetric-sign-sha256",
		ProviderID:           req.ProviderID,
		ProviderType:         "gcp_kms",
		KeyRef:               keyName,
		CanonicalPayloadHash: req.CanonicalPayloadHash,
		RequestID:            req.RequestID,
		Checks: []domain.VerifyCheck{
			{Name: "gcp_kms_signature_returned", Result: "passed", Detail: "GCP Cloud KMS returned a signature over the submitted SHA-256 digest."},
		},
	}, nil
}

func decodePayloadHash(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "sha256:") {
		return nil, app.ErrValidation
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(raw) != 32 {
		return nil, app.ErrValidation
	}
	return raw, nil
}

func validKeyName(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.ContainsAny(value, "?#") && !strings.Contains(value, "..")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
