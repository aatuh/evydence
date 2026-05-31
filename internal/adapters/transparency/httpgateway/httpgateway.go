package httpgateway

import (
	"bytes"
	"context"
	"encoding/hex"
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
	maxBodyBytes   = 128 * 1024
)

type Config struct {
	Endpoint                  string
	BearerToken               string
	Timeout                   time.Duration
	AllowInsecureForLocalhost bool
	Client                    *http.Client
}

type Fetcher struct {
	endpoint    string
	bearerToken string
	client      *http.Client
}

type proofRequest struct {
	TenantID   string `json:"tenant_id"`
	LogID      string `json:"log_id"`
	EntryID    string `json:"entry_id"`
	Endpoint   string `json:"endpoint"`
	ExternalID string `json:"external_id"`
	EntryHash  string `json:"entry_hash"`
}

type proofResponse struct {
	ExternalID     string               `json:"external_id"`
	LeafHash       string               `json:"leaf_hash"`
	RootHash       string               `json:"root_hash"`
	LeafIndex      int                  `json:"leaf_index"`
	TreeSize       int                  `json:"tree_size"`
	InclusionProof []string             `json:"inclusion_proof"`
	Checks         []domain.VerifyCheck `json:"checks,omitempty"`
	Limitations    []string             `json:"limitations,omitempty"`
}

func New(cfg Config) (*Fetcher, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, app.ErrValidation
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, app.ErrValidation
	}
	if parsed.Scheme != "https" && (!cfg.AllowInsecureForLocalhost || parsed.Scheme != "http" || !localhostHost(parsed.Hostname())) {
		return nil, errors.New("transparency proof gateway endpoint must use https")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &Fetcher{endpoint: endpoint, bearerToken: strings.TrimSpace(cfg.BearerToken), client: client}, nil
}

func (f *Fetcher) FetchTransparencyProof(ctx context.Context, req app.TransparencyProofRequest) (app.TransparencyProofResult, error) {
	if f == nil || f.client == nil {
		return app.TransparencyProofResult{}, app.ErrValidation
	}
	externalID := strings.TrimSpace(req.ExternalID)
	if externalID == "" {
		return app.TransparencyProofResult{}, app.ErrValidation
	}
	body, err := json.Marshal(proofRequest{
		TenantID:   strings.TrimSpace(req.TenantID),
		LogID:      strings.TrimSpace(req.LogID),
		EntryID:    strings.TrimSpace(req.EntryID),
		Endpoint:   strings.TrimSpace(req.Endpoint),
		ExternalID: externalID,
		EntryHash:  strings.TrimSpace(req.EntryHash),
	})
	if err != nil {
		return app.TransparencyProofResult{}, app.ErrValidation
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return app.TransparencyProofResult{}, app.ErrValidation
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	if f.bearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+f.bearerToken)
	}
	resp, err := f.client.Do(httpReq)
	if err != nil {
		return app.TransparencyProofResult{}, errors.New("transparency proof gateway request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return app.TransparencyProofResult{}, app.ErrVerificationFailed
	}
	var decoded proofResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return app.TransparencyProofResult{}, app.ErrVerificationFailed
	}
	if decoder.InputOffset() > maxBodyBytes {
		return app.TransparencyProofResult{}, app.ErrVerificationFailed
	}
	decoded.ExternalID = strings.TrimSpace(decoded.ExternalID)
	decoded.LeafHash = strings.TrimSpace(decoded.LeafHash)
	decoded.RootHash = strings.TrimSpace(decoded.RootHash)
	if decoded.ExternalID != "" && decoded.ExternalID != externalID {
		return app.TransparencyProofResult{}, app.ErrVerificationFailed
	}
	if !validSHA256Digest(decoded.RootHash) || (decoded.LeafHash != "" && !validSHA256Digest(decoded.LeafHash)) || decoded.TreeSize <= 0 || decoded.LeafIndex < 0 || decoded.LeafIndex >= decoded.TreeSize || len(decoded.InclusionProof) > 64 {
		return app.TransparencyProofResult{}, app.ErrVerificationFailed
	}
	proof := make([]string, 0, len(decoded.InclusionProof))
	for _, hash := range decoded.InclusionProof {
		hash = strings.TrimSpace(hash)
		if !validSHA256Digest(hash) {
			return app.TransparencyProofResult{}, app.ErrVerificationFailed
		}
		proof = append(proof, hash)
	}
	checks := append([]domain.VerifyCheck{{Name: "transparency_proof_gateway", Result: "passed"}}, safeChecks(decoded.Checks)...)
	limitations := safeLimitations(decoded.Limitations)
	if len(limitations) == 0 {
		limitations = []string{"Transparency proof gateway returned proof material for local verification; provider trust and timestamp semantics remain deployment responsibilities."}
	}
	return app.TransparencyProofResult{
		ExternalID:     decoded.ExternalID,
		LeafHash:       decoded.LeafHash,
		RootHash:       decoded.RootHash,
		LeafIndex:      decoded.LeafIndex,
		TreeSize:       decoded.TreeSize,
		InclusionProof: proof,
		Checks:         checks,
		Limitations:    limitations,
	}, nil
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(raw) == 32
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
