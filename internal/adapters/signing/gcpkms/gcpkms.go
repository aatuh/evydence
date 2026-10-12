package gcpkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const (
	defaultEndpoint = "https://cloudkms.googleapis.com"
	defaultTimeout  = 10 * time.Second
)

type Config struct {
	Endpoint    string
	KeyName     string
	Timeout     time.Duration
	Client      *http.Client
	TokenSource oauth2.TokenSource
}

type Executor struct {
	endpoint    string
	tokenSource oauth2.TokenSource
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

type publicKeyResponse struct {
	Name      string `json:"name,omitempty"`
	PEM       string `json:"pem"`
	Algorithm string `json:"algorithm"`
}

func New(ctx context.Context, cfg Config) (*Executor, error) {
	if cfg.TokenSource == nil {
		credentials, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return nil, errors.New("load GCP application default credentials")
		}
		cfg.TokenSource = credentials.TokenSource
	}
	return NewWithTokenSource(cfg)
}

func NewWithTokenSource(cfg Config) (*Executor, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, app.ErrValidation
	}
	if cfg.TokenSource == nil {
		return nil, app.ErrValidation
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := &http.Client{Timeout: timeout}
	if cfg.Client != nil {
		*client = *cfg.Client
		client.Timeout = timeout
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("GCP KMS redirects are not permitted") }
	return &Executor{
		endpoint:    endpoint,
		tokenSource: cfg.TokenSource,
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
	token, err := e.tokenSource.Token()
	if err != nil || strings.TrimSpace(token.AccessToken) == "" {
		return app.SigningResult{}, fmt.Errorf("%w: obtain GCP KMS access token", app.ErrRetryableSigning)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return app.SigningResult{}, fmt.Errorf("%w: execute GCP KMS signing request", app.ErrRetryableSigning)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			return app.SigningResult{}, fmt.Errorf("%w: GCP KMS signing request returned status %d", app.ErrRetryableSigning, resp.StatusCode)
		}
		return app.SigningResult{}, fmt.Errorf("gcp KMS signing request returned status %d", resp.StatusCode)
	}
	var decoded signResponse
	if err := decodeStrictJSON(resp.Body, &decoded); err != nil {
		return app.SigningResult{}, errors.New("decode GCP KMS signing response")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(decoded.Signature))
	if err != nil || len(signature) == 0 || len(signature) > 32768 {
		return app.SigningResult{}, app.ErrValidation
	}
	publicKey, err := e.fetchPublicKey(ctx, keyName, token.AccessToken)
	if err != nil {
		return app.SigningResult{}, err
	}
	if err := verifySignature(publicKey, digest, signature); err != nil {
		return app.SigningResult{}, app.ErrVerificationFailed
	}
	return app.SigningResult{
		Signature:            base64.StdEncoding.EncodeToString(signature),
		KeyID:                firstNonEmpty(strings.TrimSpace(decoded.Name), keyName),
		Algorithm:            "gcp-kms:asymmetric-sign-sha256",
		ProviderID:           req.ProviderID,
		ProviderType:         "gcp_kms",
		KeyRef:               keyName,
		CanonicalPayloadHash: req.CanonicalPayloadHash,
		RequestID:            req.RequestID,
		ProviderRequestID:    responseRequestID(resp),
		Checks: []domain.VerifyCheck{
			{Name: "gcp_kms_signature_verified", Result: "passed", Detail: "GCP Cloud KMS public key verified the signature over the submitted SHA-256 canonical-request digest."},
		},
	}, nil
}

func (e *Executor) fetchPublicKey(ctx context.Context, keyName, accessToken string) (publicKeyResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, e.endpoint+"/v1/"+strings.TrimLeft(keyName, "/")+"/publicKey", nil)
	if err != nil {
		return publicKeyResponse{}, app.ErrValidation
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := e.client.Do(request)
	if err != nil {
		return publicKeyResponse{}, fmt.Errorf("%w: fetch GCP KMS public key", app.ErrRetryableSigning)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError {
			return publicKeyResponse{}, fmt.Errorf("%w: GCP KMS public key request returned status %d", app.ErrRetryableSigning, response.StatusCode)
		}
		return publicKeyResponse{}, fmt.Errorf("gcp KMS public key request returned status %d", response.StatusCode)
	}
	var decoded publicKeyResponse
	if err := decodeStrictJSON(response.Body, &decoded); err != nil || (strings.TrimSpace(decoded.Name) != "" && strings.TrimSpace(decoded.Name) != keyName) {
		return publicKeyResponse{}, app.ErrVerificationFailed
	}
	return decoded, nil
}

func decodeStrictJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("response contains trailing data")
	}
	return nil
}

func verifySignature(response publicKeyResponse, digest, signature []byte) error {
	block, rest := pem.Decode([]byte(strings.TrimSpace(response.PEM)))
	if block == nil || len(rest) != 0 {
		return app.ErrValidation
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return app.ErrValidation
	}
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if response.Algorithm != "EC_SIGN_P256_SHA256" || !ecdsa.VerifyASN1(key, digest, signature) {
			return app.ErrVerificationFailed
		}
	case *rsa.PublicKey:
		switch {
		case strings.HasPrefix(response.Algorithm, "RSA_SIGN_PSS_") && strings.HasSuffix(response.Algorithm, "_SHA256"):
			if rsa.VerifyPSS(key, crypto.SHA256, digest, signature, nil) != nil {
				return app.ErrVerificationFailed
			}
		case strings.HasPrefix(response.Algorithm, "RSA_SIGN_PKCS1_") && strings.HasSuffix(response.Algorithm, "_SHA256"):
			if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, signature) != nil {
				return app.ErrVerificationFailed
			}
		default:
			return app.ErrValidation
		}
	default:
		return app.ErrValidation
	}
	return nil
}

func responseRequestID(response *http.Response) string {
	requestID := strings.TrimSpace(response.Header.Get("x-goog-request-id"))
	if len(requestID) > 256 || strings.ContainsAny(requestID, "\r\n") {
		return ""
	}
	return requestID
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
	return value != "" && strings.Contains(value, "/cryptoKeyVersions/") && !strings.ContainsAny(value, "?#") && !strings.Contains(value, "..")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
