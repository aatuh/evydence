package azurekeyvault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const (
	defaultAPIVersion = "7.4"
	defaultAlgorithm  = "ES256"
	defaultTimeout    = 10 * time.Second
)

type Config struct {
	VaultURL   string
	Credential azcore.TokenCredential
	KeyName    string
	KeyVersion string
	Algorithm  string
	APIVersion string
	Timeout    time.Duration
	Client     *http.Client
}

type Executor struct {
	vaultURL   string
	credential azcore.TokenCredential
	keyName    string
	keyVersion string
	algorithm  string
	apiVersion string
	client     *http.Client
}

type signRequest struct {
	Algorithm string `json:"alg"`
	Value     string `json:"value"`
}

type signResponse struct {
	KeyID string `json:"kid,omitempty"`
	Value string `json:"value"`
}

type keyResponse struct {
	Key struct {
		KeyID string `json:"kid"`
		KTY   string `json:"kty"`
		CRV   string `json:"crv"`
		X     string `json:"x"`
		Y     string `json:"y"`
	} `json:"key"`
}

func New(cfg Config) (*Executor, error) {
	if cfg.Credential == nil {
		credential, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, errors.New("load Azure default credentials")
		}
		cfg.Credential = credential
	}
	return NewWithCredential(cfg)
}

func NewWithCredential(cfg Config) (*Executor, error) {
	vaultURL := strings.TrimRight(strings.TrimSpace(cfg.VaultURL), "/")
	if vaultURL == "" {
		return nil, app.ErrValidation
	}
	parsed, err := url.Parse(vaultURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, app.ErrValidation
	}
	if cfg.Credential == nil {
		return nil, app.ErrValidation
	}
	algorithm := strings.TrimSpace(cfg.Algorithm)
	if algorithm == "" {
		algorithm = defaultAlgorithm
	}
	if algorithm != defaultAlgorithm {
		return nil, errors.New("unsupported Azure Key Vault signing algorithm")
	}
	apiVersion := strings.TrimSpace(cfg.APIVersion)
	if apiVersion == "" {
		apiVersion = defaultAPIVersion
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
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("azure Key Vault redirects are not permitted")
	}
	return &Executor{
		vaultURL:   vaultURL,
		credential: cfg.Credential,
		keyName:    strings.TrimSpace(cfg.KeyName),
		keyVersion: strings.TrimSpace(cfg.KeyVersion),
		algorithm:  algorithm,
		apiVersion: apiVersion,
		client:     client,
	}, nil
}

func (e *Executor) Sign(ctx context.Context, req app.SigningRequest) (app.SigningResult, error) {
	if e == nil || e.client == nil {
		return app.SigningResult{}, app.ErrValidation
	}
	if providerType := strings.TrimSpace(req.ProviderType); providerType != "" && providerType != "azure_key_vault" {
		return app.SigningResult{}, app.ErrValidation
	}
	digest, err := decodePayloadHash(req.CanonicalPayloadHash)
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
	token, err := e.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://vault.azure.net/.default"}})
	if err != nil || strings.TrimSpace(token.Token) == "" {
		return app.SigningResult{}, fmt.Errorf("%w: obtain Azure Key Vault access token", app.ErrRetryableSigning)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token.Token)
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return app.SigningResult{}, fmt.Errorf("%w: execute Azure Key Vault signing request", app.ErrRetryableSigning)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			return app.SigningResult{}, fmt.Errorf("%w: Azure Key Vault signing request returned status %d", app.ErrRetryableSigning, resp.StatusCode)
		}
		return app.SigningResult{}, fmt.Errorf("azure Key Vault signing request returned status %d", resp.StatusCode)
	}
	var decoded signResponse
	if err := decodeStrictJSON(resp.Body, &decoded); err != nil {
		return app.SigningResult{}, errors.New("decode Azure Key Vault signing response")
	}
	signature, err := normalizeBase64URLSignature(decoded.Value)
	if err != nil || len(signature) > 32768 {
		return app.SigningResult{}, app.ErrValidation
	}
	keyURL := vaultURL + "/keys/" + keyName + "/" + keyVersion
	if decodedKeyID := strings.TrimSpace(decoded.KeyID); decodedKeyID != "" && decodedKeyID != keyURL {
		return app.SigningResult{}, app.ErrVerificationFailed
	}
	publicKey, err := e.fetchPublicKey(ctx, keyURL, token.Token)
	if err != nil {
		return app.SigningResult{}, err
	}
	if err := verifySignature(publicKey, digest, signature); err != nil {
		return app.SigningResult{}, app.ErrVerificationFailed
	}
	return app.SigningResult{
		Signature:            signature,
		KeyID:                firstNonEmpty(strings.TrimSpace(decoded.KeyID), keyURL),
		Algorithm:            "azure-key-vault:" + e.algorithm,
		ProviderID:           req.ProviderID,
		ProviderType:         "azure_key_vault",
		KeyRef:               req.KeyRef,
		CanonicalPayloadHash: req.CanonicalPayloadHash,
		RequestID:            req.RequestID,
		ProviderRequestID:    responseRequestID(resp),
		Checks: []domain.VerifyCheck{
			{Name: "azure_key_vault_signature_verified", Result: "passed", Detail: "Azure Key Vault public key verified the signature over the submitted SHA-256 canonical-request digest."},
		},
	}, nil
}

func (e *Executor) fetchPublicKey(ctx context.Context, keyURL, accessToken string) (keyResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL+"?api-version="+url.QueryEscape(e.apiVersion), nil)
	if err != nil {
		return keyResponse{}, app.ErrValidation
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := e.client.Do(request)
	if err != nil {
		return keyResponse{}, fmt.Errorf("%w: fetch Azure Key Vault public key", app.ErrRetryableSigning)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError {
			return keyResponse{}, fmt.Errorf("%w: Azure Key Vault public key request returned status %d", app.ErrRetryableSigning, response.StatusCode)
		}
		return keyResponse{}, fmt.Errorf("azure Key Vault public key request returned status %d", response.StatusCode)
	}
	var decoded keyResponse
	if err := decodeStrictJSON(response.Body, &decoded); err != nil || strings.TrimSpace(decoded.Key.KeyID) != keyURL {
		return keyResponse{}, app.ErrVerificationFailed
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

func verifySignature(response keyResponse, digest []byte, signature string) error {
	if response.Key.KTY != "EC" || response.Key.CRV != "P-256" {
		return app.ErrValidation
	}
	x, err := base64.RawURLEncoding.DecodeString(response.Key.X)
	if err != nil {
		return app.ErrValidation
	}
	y, err := base64.RawURLEncoding.DecodeString(response.Key.Y)
	if err != nil || len(x) != 32 || len(y) != 32 {
		return app.ErrValidation
	}
	encodedPoint := append([]byte{4}, append(x, y...)...)
	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encodedPoint)
	if err != nil {
		return app.ErrValidation
	}
	rawSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(rawSignature) != 64 {
		return app.ErrValidation
	}
	derSignature, err := ecdsaSignatureDER(rawSignature)
	if err != nil || !ecdsa.VerifyASN1(publicKey, digest, derSignature) {
		return app.ErrVerificationFailed
	}
	return nil
}

func ecdsaSignatureDER(raw []byte) ([]byte, error) {
	return asn1.Marshal(struct {
		R, S *big.Int
	}{R: new(big.Int).SetBytes(raw[:32]), S: new(big.Int).SetBytes(raw[32:])})
}

func responseRequestID(response *http.Response) string {
	requestID := strings.TrimSpace(response.Header.Get("x-ms-request-id"))
	if len(requestID) > 256 || strings.ContainsAny(requestID, "\r\n") {
		return ""
	}
	return requestID
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
