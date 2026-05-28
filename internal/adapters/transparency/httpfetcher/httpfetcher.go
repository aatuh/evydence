package httpfetcher

import (
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
	maxProofBytes  = 128 * 1024
)

type Config struct {
	Timeout                   time.Duration
	AllowInsecureForLocalhost bool
	Client                    *http.Client
}

type Fetcher struct {
	client                    *http.Client
	allowInsecureForLocalhost bool
}

type proofResponse struct {
	ExternalID     string   `json:"external_id"`
	LeafHash       string   `json:"leaf_hash"`
	RootHash       string   `json:"root_hash"`
	LeafIndex      int      `json:"leaf_index"`
	TreeSize       int      `json:"tree_size"`
	InclusionProof []string `json:"inclusion_proof"`
}

func New(cfg Config) *Fetcher {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Fetcher{client: client, allowInsecureForLocalhost: cfg.AllowInsecureForLocalhost}
}

func (f *Fetcher) FetchTransparencyProof(ctx context.Context, req app.TransparencyProofRequest) (app.TransparencyProofResult, error) {
	if f == nil || f.client == nil {
		return app.TransparencyProofResult{}, app.ErrValidation
	}
	externalID := strings.TrimSpace(req.ExternalID)
	if externalID == "" {
		return app.TransparencyProofResult{}, app.ErrValidation
	}
	endpoint, err := parseEndpoint(req.Endpoint, f.allowInsecureForLocalhost)
	if err != nil {
		return app.TransparencyProofResult{}, err
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/entries/" + url.PathEscape(externalID) + "/inclusion-proof"
	endpoint.RawQuery = ""
	endpoint.Fragment = ""

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return app.TransparencyProofResult{}, app.ErrValidation
	}
	httpReq.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(httpReq)
	if err != nil {
		return app.TransparencyProofResult{}, errors.New("fetch transparency proof")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return app.TransparencyProofResult{}, app.ErrVerificationFailed
	}
	var decoded proofResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxProofBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return app.TransparencyProofResult{}, app.ErrVerificationFailed
	}
	if decoder.InputOffset() > maxProofBytes {
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
	return app.TransparencyProofResult{
		ExternalID:     decoded.ExternalID,
		LeafHash:       decoded.LeafHash,
		RootHash:       decoded.RootHash,
		LeafIndex:      decoded.LeafIndex,
		TreeSize:       decoded.TreeSize,
		InclusionProof: proof,
		Checks:         []domain.VerifyCheck{{Name: "public_log_proof_fetch", Result: "passed"}},
		Limitations:    []string{"Fetched public-log proof material is validated locally; endpoint trust and provider semantics remain deployment responsibilities."},
	}, nil
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(raw) == 32
}

func parseEndpoint(raw string, allowInsecureLocalhost bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, app.ErrValidation
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if parsed.Scheme == "http" && allowInsecureLocalhost && localhostHost(parsed.Hostname()) {
		return parsed, nil
	}
	return nil, app.ErrValidation
}

func localhostHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
