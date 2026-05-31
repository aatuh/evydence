package oidcuserinfo

import (
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

const defaultTimeout = 10 * time.Second

type Config struct {
	Timeout                   time.Duration
	AllowInsecureForLocalhost bool
	Client                    *http.Client
}

type Validator struct {
	client                    *http.Client
	allowInsecureForLocalhost bool
}

type discoveryDocument struct {
	UserInfoEndpoint string `json:"userinfo_endpoint"`
}

type userInfoDocument map[string]any

func New(cfg Config) *Validator {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &Validator{client: client, allowInsecureForLocalhost: cfg.AllowInsecureForLocalhost}
}

func (v *Validator) ValidateProviderIdentity(ctx context.Context, req app.ProviderIdentityValidationRequest) (app.ProviderIdentityValidationResult, error) {
	if v == nil || v.client == nil {
		return app.ProviderIdentityValidationResult{}, app.ErrValidation
	}
	if strings.TrimSpace(req.ProviderType) != "oidc" || strings.TrimSpace(req.Subject) == "" || strings.TrimSpace(req.AccessToken) == "" || len(strings.TrimSpace(req.AccessToken)) > 16*1024 {
		return app.ProviderIdentityValidationResult{}, app.ErrValidation
	}
	issuer, err := validateURL(req.Issuer, v.allowInsecureForLocalhost)
	if err != nil {
		return failed("oidc_issuer_url"), app.ErrValidation
	}
	discoveryURL := issuer.JoinPath(".well-known", "openid-configuration").String()
	var discovery discoveryDocument
	if err := v.getJSON(ctx, discoveryURL, "", &discovery); err != nil {
		return failed("oidc_discovery_fetch"), app.ErrVerificationFailed
	}
	userInfoURL, err := validateURL(discovery.UserInfoEndpoint, v.allowInsecureForLocalhost)
	if err != nil {
		return failed("oidc_userinfo_endpoint"), app.ErrVerificationFailed
	}
	var info userInfoDocument
	if err := v.getJSON(ctx, userInfoURL.String(), req.AccessToken, &info); err != nil {
		return failed("oidc_userinfo_fetch"), app.ErrVerificationFailed
	}
	subject, _ := info["sub"].(string)
	if strings.TrimSpace(subject) == "" || subject != strings.TrimSpace(req.Subject) {
		return app.ProviderIdentityValidationResult{Checks: []domain.VerifyCheck{
			{Name: "oidc_discovery_fetch", Result: "passed"},
			{Name: "oidc_userinfo_fetch", Result: "passed"},
			{Name: "oidc_userinfo_subject", Result: "failed"},
		}, Limitations: limitations()}, app.ErrVerificationFailed
	}
	groups := groupsFromUserInfo(info, req.GroupsClaim)
	checks := []domain.VerifyCheck{
		{Name: "oidc_discovery_fetch", Result: "passed"},
		{Name: "oidc_userinfo_fetch", Result: "passed"},
		{Name: "oidc_userinfo_subject", Result: "passed"},
	}
	if strings.TrimSpace(req.GroupsClaim) != "" {
		if len(groups) == 0 {
			checks = append(checks, domain.VerifyCheck{Name: "oidc_userinfo_groups", Result: "warning", Detail: "Configured groups claim was absent or empty in UserInfo."})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "oidc_userinfo_groups", Result: "passed"})
		}
	}
	return app.ProviderIdentityValidationResult{Checks: checks, Groups: groups, Limitations: limitations()}, nil
}

func (v *Validator) getJSON(ctx context.Context, endpoint, bearerToken string, target any) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Accept", "application/json")
	if bearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	resp, err := v.client.Do(httpReq)
	if err != nil {
		return errors.New("provider request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return errors.New("provider request failed")
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(target); err != nil {
		return errors.New("provider response decode failed")
	}
	return nil
}

func validateURL(value string, allowInsecureLocalhost bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("invalid provider url")
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if parsed.Scheme == "http" && allowInsecureLocalhost && localhostHost(parsed.Hostname()) {
		return parsed, nil
	}
	return nil, errors.New("provider url must use https")
}

func localhostHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func groupsFromUserInfo(info userInfoDocument, claim string) []string {
	claim = strings.TrimSpace(claim)
	if claim == "" {
		return nil
	}
	raw, ok := info[claim]
	if !ok {
		return nil
	}
	groups := []string{}
	switch typed := raw.(type) {
	case []any:
		for _, item := range typed {
			if value, ok := item.(string); ok && strings.TrimSpace(value) != "" {
				groups = append(groups, strings.TrimSpace(value))
			}
		}
	case []string:
		for _, item := range typed {
			if strings.TrimSpace(item) != "" {
				groups = append(groups, strings.TrimSpace(item))
			}
		}
	case string:
		if strings.TrimSpace(typed) != "" {
			groups = append(groups, strings.TrimSpace(typed))
		}
	}
	return groups
}

func failed(name string) app.ProviderIdentityValidationResult {
	return app.ProviderIdentityValidationResult{
		Checks:      []domain.VerifyCheck{{Name: name, Result: "failed"}},
		Limitations: limitations(),
	}
}

func limitations() []string {
	return []string{"Live OIDC UserInfo validation used a supplied bearer access token; Evydence does not store the token and does not synchronize provider groups permanently."}
}
