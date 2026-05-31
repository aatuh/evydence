package azurekeyvault

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
	defaultAPIVersion = "7.4"
	defaultAlgorithm  = "ES256"
	defaultTimeout    = 10 * time.Second
)

type Config struct {
	VaultURL    string
	AccessToken string
	KeyName     string
	KeyVersion  string
	Algorithm   string
	APIVersion  string
	Timeout     time.Duration
	Client      *http.Client
}

type Executor struct {
	vaultURL    string
	accessToken string
	keyName     string
	keyVersion  string
	algorithm   string
	apiVersion  string
	client      *http.Client
}

type signRequest struct {
	Algorithm string `json:"alg"`
	Value     string `json:"value"`
}

type signResponse struct {
	KeyID string `json:"kid,omitempty"`
	Value string `json:"value"`
}

func New(cfg Config) (*Executor, error) {
	vaultURL := strings.TrimRight(strings.TrimSpace(cfg.VaultURL), "/")
	if vaultURL == "" {
		return nil, app.ErrValidation
	}
	parsed, err := url.Parse(vaultURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, app.ErrValidation
	}
	if strings.TrimSpace(cfg.AccessToken) == "" {
		return nil, errors.New("configure Azure Key Vault access token")
	}
	algorithm := strings.TrimSpace(cfg.Algorithm)
	if algorithm == "" {
		algorithm = defaultAlgorithm
	}
	apiVersion := strings.TrimSpace(cfg.APIVersion)
	if apiVersion == "" {
		apiVersion = defaultAPIVersion
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
		vaultURL:    vaultURL,
		accessToken: strings.TrimSpace(cfg.AccessToken),
		keyName:     strings.TrimSpace(cfg.KeyName),
		keyVersion:  strings.TrimSpace(cfg.KeyVersion),
		algorithm:   algorithm,
		apiVersion:  apiVersion,
		client:      client,
	}, nil
}

func (e *Executor) Sign(ctx context.Context, req app.SigningRequest) (app.SigningResult, error) {
	if e == nil || e.client == nil {
		return app.SigningResult{}, app.ErrValidation
	}
	if providerType := strings.TrimSpace(req.ProviderType); providerType != "" && providerType != "azure_key_vault" {
		return app.SigningResult{}, app.ErrValidation
	}
	digest, err := decodePayloadHash(req.PayloadHash)
	if err != nil {
		return app.SigningResult{}, err
	}
	vaultURL, keyName, keyVersion, err := e.resolveKey(req.KeyRef)
	if err != nil {
		return app.SigningResult{}, err
	}
	body, err := json.Marshal(signRequest{Algorithm: e.algorithm, Value: base64.RawURLEncoding.EncodeToString(digest)})
	if err != nil {
		return app.SigningResult{}, app.ErrValidation
	}
	signURL := fmt.Sprintf("%s/keys/%s/%s/sign?api-version=%s", vaultURL, url.PathEscape(keyName), url.PathEscape(keyVersion), url.QueryEscape(e.apiVersion))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, signURL, bytes.NewReader(body))
	if err != nil {
		return app.SigningResult{}, app.ErrValidation
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+e.accessToken)
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return app.SigningResult{}, errors.New("execute Azure Key Vault signing request")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return app.SigningResult{}, fmt.Errorf("azure Key Vault signing request returned status %d", resp.StatusCode)
	}
	var decoded signResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return app.SigningResult{}, errors.New("decode Azure Key Vault signing response")
	}
	signature, err := normalizeBase64URLSignature(decoded.Value)
	if err != nil || len(signature) > 32768 {
		return app.SigningResult{}, app.ErrValidation
	}
	return app.SigningResult{
		Signature: signature,
		KeyID:     firstNonEmpty(strings.TrimSpace(decoded.KeyID), vaultURL+"/keys/"+keyName+"/"+keyVersion),
		Algorithm: "azure-key-vault:" + e.algorithm,
		Checks: []domain.VerifyCheck{
			{Name: "azure_key_vault_signature_returned", Result: "passed", Detail: "Azure Key Vault returned a signature over the submitted SHA-256 digest."},
		},
	}, nil
}

func (e *Executor) resolveKey(keyRef string) (string, string, string, error) {
	keyRef = strings.TrimSpace(keyRef)
	if keyRef != "" && strings.HasPrefix(keyRef, "https://") {
		parsed, err := url.Parse(keyRef)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return "", "", "", app.ErrValidation
		}
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) < 3 || parts[0] != "keys" || !validSegment(parts[1]) || !validSegment(parts[2]) {
			return "", "", "", app.ErrValidation
		}
		return parsed.Scheme + "://" + parsed.Host, parts[1], parts[2], nil
	}
	keyName := firstNonEmpty(keyRef, e.keyName)
	keyVersion := e.keyVersion
	if !validSegment(keyName) || !validSegment(keyVersion) {
		return "", "", "", app.ErrValidation
	}
	return e.vaultURL, keyName, keyVersion, nil
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

func normalizeBase64URLSignature(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", app.ErrValidation
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(value)
	}
	if err != nil || len(raw) == 0 {
		return "", app.ErrValidation
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func validSegment(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.ContainsAny(value, "/?#") && !strings.Contains(value, "..")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
