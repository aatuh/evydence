package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/platform/telemetry"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

type loggingProviderFixture struct {
	err error
	ctx context.Context
}

type providerObservationFixture struct{ events []telemetry.Event }

func (f *providerObservationFixture) Observe(_ context.Context, event telemetry.Event) {
	f.events = append(f.events, event)
}

func (f *loggingProviderFixture) Sign(ctx context.Context, r app.SigningRequest) (app.SigningResult, error) {
	f.ctx = ctx
	return app.SigningResult{Signature: "CANARY_SIGNATURE", ProviderRequestID: "CANARY_PROVIDER_RECEIPT"}, f.err
}
func (f *loggingProviderFixture) FetchOIDCTrustMaterial(ctx context.Context, r app.OIDCDiscoveryRequest) (app.OIDCDiscoveryResult, error) {
	f.ctx = ctx
	return app.OIDCDiscoveryResult{Issuer: "CANARY_ISSUER"}, f.err
}
func (f *loggingProviderFixture) ValidateProviderIdentity(ctx context.Context, r app.ProviderIdentityValidationRequest) (app.ProviderIdentityValidationResult, error) {
	f.ctx = ctx
	return app.ProviderIdentityValidationResult{Groups: []string{"CANARY_GROUP"}}, f.err
}
func (f *loggingProviderFixture) FetchTransparencyProof(ctx context.Context, r app.TransparencyProofRequest) (app.TransparencyProofResult, error) {
	f.ctx = ctx
	return app.TransparencyProofResult{ExternalID: "CANARY_EXTERNAL"}, f.err
}
func (f *loggingProviderFixture) VerifyCosign(ctx context.Context, r app.CosignVerificationRequest) (app.CosignVerificationReceipt, error) {
	f.ctx = ctx
	return app.CosignVerificationReceipt{LibraryVersion: "CANARY_RESPONSE"}, f.err
}

func TestProviderLoggingCoversEveryPortAndNeverSerializesInputsOutputsOrErrors(t *testing.T) {
	for _, failure := range []error{nil, errors.New("CANARY_RAW_PROVIDER_ERROR")} {
		for _, kind := range []string{"signing", "oidc", "identity", "transparency", "cosign"} {
			t.Run(kind+map[bool]string{true: "-failure", false: "-success"}[failure != nil], func(t *testing.T) {
				var out bytes.Buffer
				logger, err := logging.New(&out, "api", runtimeinfo.Current(), logging.Config{})
				if err != nil {
					t.Fatal(err)
				}
				observations := &providerObservationFixture{}
				ctx := telemetry.WithObserver(logging.WithRequest(logging.WithLogger(t.Context(), logger), "CANARY_REQUEST"), observations)
				provider := &loggingProviderFixture{err: failure}
				switch kind {
				case "signing":
					v, err := observeSigningExecutor(provider).Sign(ctx, app.SigningRequest{TenantID: "CANARY_TENANT", SubjectID: "CANARY_RESOURCE", KeyRef: "CANARY_KEY", Nonce: "CANARY_NONCE"})
					if !errors.Is(err, failure) || v.Signature != "CANARY_SIGNATURE" {
						t.Fatal("signing result changed")
					}
				case "oidc":
					v, err := observeOIDC(provider).FetchOIDCTrustMaterial(ctx, app.OIDCDiscoveryRequest{TenantID: "CANARY_TENANT", ProviderID: "CANARY_RESOURCE", Issuer: "CANARY_URL"})
					if !errors.Is(err, failure) || v.Issuer != "CANARY_ISSUER" {
						t.Fatal("OIDC result changed")
					}
				case "identity":
					v, err := observeIdentityProvider(provider).ValidateProviderIdentity(ctx, app.ProviderIdentityValidationRequest{TenantID: "CANARY_TENANT", ProviderID: "CANARY_RESOURCE", AccessToken: "CANARY_TOKEN", Subject: "CANARY_SUBJECT"})
					if !errors.Is(err, failure) || len(v.Groups) != 1 {
						t.Fatal("identity result changed")
					}
				case "transparency":
					v, err := observeTransparency(provider).FetchTransparencyProof(ctx, app.TransparencyProofRequest{TenantID: "CANARY_TENANT", EntryID: "CANARY_RESOURCE", Endpoint: "CANARY_URL", ExternalID: "CANARY_EXTERNAL"})
					if !errors.Is(err, failure) || v.ExternalID != "CANARY_EXTERNAL" {
						t.Fatal("transparency result changed")
					}
				case "cosign":
					v, err := observeCosign(provider).VerifyCosign(ctx, app.CosignVerificationRequest{Bundle: []byte("CANARY_RAW_EVIDENCE"), ArtifactDigest: "CANARY_RESOURCE", ExpectedIdentity: "CANARY_SUBJECT"})
					if !errors.Is(err, failure) || v.LibraryVersion != "CANARY_RESPONSE" {
						t.Fatal("cosign result changed")
					}
				}
				if provider.ctx != ctx {
					t.Fatal("provider cancellation/correlation context changed")
				}
				wantOperation := map[string]telemetry.Operation{
					"signing":      telemetry.OperationProviderSign,
					"oidc":         telemetry.OperationProviderOIDCDiscovery,
					"identity":     telemetry.OperationProviderIdentity,
					"transparency": telemetry.OperationProviderTransparency,
					"cosign":       telemetry.OperationProviderCosign,
				}[kind]
				wantOutcome := telemetry.OutcomeSucceeded
				if failure != nil {
					wantOutcome = telemetry.OutcomeFailed
				}
				if len(observations.events) != 1 {
					t.Fatal("provider call did not record exactly one operational observation", len(observations.events))
				}
				measured := observations.events[0]
				if measured.Operation != wantOperation || measured.Outcome != wantOutcome || measured.Duration < 0 || measured.Attempt != 0 {
					t.Fatal("provider observation lost its fixed operation, result or duration", measured)
				}
				if strings.Contains(out.String(), "CANARY") {
					t.Fatal("provider secret leaked")
				}
				var event map[string]any
				if err := json.Unmarshal(out.Bytes(), &event); err != nil {
					t.Fatal(err)
				}
				expected := "succeeded"
				if failure != nil {
					expected = "failed"
				}
				if event["msg"] != "provider" || event["request_id"] != logging.CorrelationFromContext(ctx).RequestID || event["result_code"] != expected {
					t.Fatal("provider correlation or outcome lost")
				}
			})
		}
	}
	if observeSigningExecutor(nil) != nil || observeOIDC(nil) != nil || observeIdentityProvider(nil) != nil || observeTransparency(nil) != nil || observeCosign(nil) != nil {
		t.Fatal("optional missing provider became configured")
	}
}
