package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type trustGuardAuthorizer struct {
	calls   int
	err     error
	actor   identitydomain.Actor
	request application.AuthorizationRequest
}

func (a *trustGuardAuthorizer) Authorize(_ context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	a.calls++
	a.actor, a.request = actor, request
	return a.err
}

type trustGuardTransactions struct {
	calls      int
	authorizer application.Authorizer
}

func (x *trustGuardTransactions) ExecuteTrustConfigurationCommand(ctx context.Context, fn func(context.Context, TrustConfigurationTransaction) error) error {
	x.calls++
	// Write ports deliberately remain nil: the replay guard must only authorize.
	return fn(ctx, serviceTrustConfigurationTransaction{Authorizer: x.authorizer})
}
func TestTrustConfigurationReplayGuardHasNoMetadataOrAuditEffects(t *testing.T) {
	for _, stage := range []string{"allowed", "policy", "transaction", "cancelled", "nil-context", "invalid-actor"} {
		t.Run(stage, func(t *testing.T) {
			policy, txPolicy := &trustGuardAuthorizer{}, &trustGuardAuthorizer{}
			tx := &trustGuardTransactions{authorizer: txPolicy}
			c, err := NewTrustConfigurationCommands(TrustConfigurationConfig{Transactions: tx, Authorizer: policy,
				Clock: application.ClockFunc(func() time.Time { t.Fatal("guard read clock"); return time.Time{} }),
				IDs:   application.IDGeneratorFunc(func(string) string { t.Fatal("guard generated ID"); return "" })})
			if err != nil {
				t.Fatal(err)
			}
			ctx, actor, want := t.Context(), verificationTestActor(), error(nil)
			policyCalls, txCalls := 1, 1
			switch stage {
			case "policy":
				policy.err, want, txCalls = application.ErrForbidden, application.ErrForbidden, 0
			case "transaction":
				txPolicy.err, want = application.ErrForbidden, application.ErrForbidden
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want, policyCalls, txCalls = context.Canceled, 0, 0
			case "nil-context":
				ctx = nil
				want, policyCalls, txCalls = context.Canceled, 0, 0
			case "invalid-actor":
				actor.TenantID = ""
				want, policyCalls, txCalls = ErrForbidden, 0, 0
			}
			if err := c.AuthorizeTrustConfiguration(ctx, actor); !errors.Is(err, want) || policy.calls != policyCalls || tx.calls != txCalls || txPolicy.calls != txCalls {
				t.Fatal("guard bypassed current authorization", err, policy.calls, tx.calls, txPolicy.calls)
			}
			for _, a := range []*trustGuardAuthorizer{policy, txPolicy} {
				if a.calls > 0 && (a.actor.TenantID != actor.TenantID || a.request != (application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true})) {
					t.Fatal("guard widened admin policy")
				}
			}
		})
	}
}

func trustRootInput() CreateDSSETrustRootInput {
	return CreateDSSETrustRootInput{Name: "builder", KeyID: "builder-key", Algorithm: "Ed25519", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedPredicateTypes: []string{"https://slsa.dev/provenance/v1"}, ExpectedBuilderIDs: []string{"https://ci.example.test/builder"}, RequiredClaims: []string{"builder_id"}}
}
func TestTrustConfigurationRejectsUnsafeDatabaseTextAndUnboundedPolicies(t *testing.T) {
	for _, input := range []CreateSigningProviderInput{
		{Name: "bad\x00name", Type: "aws_kms", KeyRef: "key"},
		{Name: string([]byte{0xff}), Type: "aws_kms", KeyRef: "key"},
		{Name: strings.Repeat("n", 4097), Type: "aws_kms", KeyRef: "key"},
		{Name: "KMS", Type: "aws_kms", KeyRef: "key\x00ref"},
		{Name: "KMS", Type: "aws_kms", KeyRef: strings.Repeat("k", 4097)},
		{Name: "KMS", Type: "aws_kms", KeyRef: "key?password=private-secret"},
		{Name: strings.Repeat(" ", 4096) + "KMS", Type: "aws_kms", KeyRef: "key"},
		{Name: "KMS", Type: strings.Repeat(" ", 4096) + "aws_kms", KeyRef: "key"},
		{Name: "KMS", Type: "aws_kms", KeyRef: strings.Repeat(" ", 4096) + "key"},
	} {
		state := newVerificationTestState()
		service := newVerificationTestService(t, state)
		if _, err := service.CreateSigningProvider(t.Context(), verificationTestActor(), input); !errors.Is(err, ErrValidation) || len(state.providers) != 0 || len(state.audit) != 0 {
			t.Fatal("unsafe provider persisted", err)
		}
	}
	for _, mutate := range []func(*CreateDSSETrustRootInput){
		func(v *CreateDSSETrustRootInput) { v.Name = "bad\x00name" },
		func(v *CreateDSSETrustRootInput) { v.KeyID = strings.Repeat("k", 1025) },
		func(v *CreateDSSETrustRootInput) { v.ExpectedBuilderIDs = []string{"builder\x00id"} },
		func(v *CreateDSSETrustRootInput) { v.ExpectedBuilderIDs = []string{string([]byte{0xff})} },
		func(v *CreateDSSETrustRootInput) { v.ExpectedBuilderIDs = make([]string, 4097) },
		func(v *CreateDSSETrustRootInput) { v.ExpectedBuilderIDs = []string{strings.Repeat("b", 4097)} },
		func(v *CreateDSSETrustRootInput) { v.Name = strings.Repeat(" ", 4096) + "builder" },
		func(v *CreateDSSETrustRootInput) { v.KeyID = strings.Repeat(" ", 1024) + "key" },
		func(v *CreateDSSETrustRootInput) { v.Algorithm = strings.Repeat(" ", 4096) + "Ed25519" },
		func(v *CreateDSSETrustRootInput) { v.PublicKey = strings.Repeat(" ", 128) + v.PublicKey },
	} {
		state := newVerificationTestState()
		service := newVerificationTestService(t, state)
		input := trustRootInput()
		mutate(&input)
		if _, err := service.CreateDSSETrustRoot(t.Context(), verificationTestActor(), input); !errors.Is(err, ErrValidation) || len(state.roots) != 0 || len(state.audit) != 0 {
			t.Fatal("unsafe trust root persisted", err)
		}
	}
}

func TestTrustPolicyBoundsApplyToCombinedListsWithoutTruncation(t *testing.T) {
	input := CreateDSSETrustRootInput{ExpectedBuilderIDs: make([]string, MaxTrustPolicyEntries)}
	for i := range input.ExpectedBuilderIDs {
		input.ExpectedBuilderIDs[i] = "builder"
	}
	if !boundedTrustPolicy(input) {
		t.Fatal("exact entry budget rejected")
	}
	input.RequiredClaims = []string{"builder_id"}
	if boundedTrustPolicy(input) {
		t.Fatal("combined entry overflow accepted")
	}
	input = CreateDSSETrustRootInput{ExpectedBuilderIDs: make([]string, MaxTrustPolicyTextBytes/4096)}
	for i := range input.ExpectedBuilderIDs {
		input.ExpectedBuilderIDs[i] = strings.Repeat("b", 4096)
	}
	if !boundedTrustPolicy(input) {
		t.Fatal("exact text budget rejected")
	}
	input.RequiredClaims = []string{"builder_id"}
	if boundedTrustPolicy(input) {
		t.Fatal("combined text overflow accepted")
	}
}

func TestTrustConfigurationRawScalarBoundaryPreservesNormalization(t *testing.T) {
	in := CreateSigningProviderInput{Name: strings.Repeat("é", 2048), Type: " aws_kms ", KeyRef: strings.Repeat(" ", 4093) + "key"}
	v, err := NormalizeSigningProviderInput(in)
	if err != nil || v.Name != in.Name || v.Type != "aws_kms" || v.KeyRef != "key" {
		t.Fatal("exact raw provider bounds changed", err)
	}
	in.Name += "é"
	if _, err := NormalizeSigningProviderInput(in); !errors.Is(err, ErrValidation) {
		t.Fatal("multibyte overflow accepted", err)
	}
	root := trustRootInput()
	root.Name = strings.Repeat(" ", 4089) + "builder"
	root.KeyID = strings.Repeat(" ", 1021) + "key"
	root.PublicKey = strings.Repeat(" ", 128-len(root.PublicKey)) + root.PublicKey
	root.ExpectedBuilderIDs = []string{" other ", " builder "}
	got, err := NormalizeDSSETrustRootInput(root)
	if err != nil || got.Name != "builder" || got.KeyID != "key" || len(got.PublicKey) != 44 || got.ExpectedBuilderIDs[0] != "builder" || got.ExpectedBuilderIDs[1] != "other" {
		t.Fatal("exact raw trust bounds changed", err)
	}
	got.ExpectedBuilderIDs[0] = "changed"
	if root.ExpectedBuilderIDs[0] != " other " {
		t.Fatal("normalization aliases caller policy")
	}
}

func TestFocusedTrustConfigurationCommandsPreserveAtomicMetadataAndOwnedCopies(t *testing.T) {
	for _, failure := range []bool{false, true} {
		state := newVerificationTestState()
		service := newVerificationTestService(t, state)
		commands, err := NewTrustConfigurationCommands(TrustConfigurationConfig{Transactions: serviceTrustConfigurationTransactions{state}, Authorizer: service.authorizer, Clock: service.clock, IDs: service.ids})
		if err != nil {
			t.Fatal(err)
		}
		if failure {
			state.auditErr = errVerificationTestFailure
		}
		provider, err := commands.CreateSigningProvider(t.Context(), verificationTestActor(), CreateSigningProviderInput{Name: " KMS ", Type: "aws_kms", KeyRef: " key ", Encrypted: true})
		if failure {
			if !errors.Is(err, errVerificationTestFailure) || provider.ID != "" || len(state.providers) != 0 {
				t.Fatal("audit failure published provider", err)
			}
		} else if err != nil || provider.Name != "KMS" || provider.KeyRef != "key" || provider.Status != "active" || state.audit[0].EntryType != "signing_provider.created" {
			t.Fatal(provider, err)
		}
		input := trustRootInput()
		input.RequiredClaims = []string{"external_parameters", "builder_id"}
		root, err := commands.CreateDSSETrustRoot(t.Context(), verificationTestActor(), input)
		if failure {
			if !errors.Is(err, errVerificationTestFailure) || root.ID != "" || len(state.roots) != 0 || len(state.audit) != 0 {
				t.Fatal("audit failure published trust root", err)
			}
			continue
		}
		if err != nil || root.SchemaVersion != verificationdomain.DSSETrustRootSchemaVersion || root.RequiredClaims[0] != "builder_id" || len(state.audit) != 2 {
			t.Fatal(root, err)
		}
		root.ExpectedBuilderIDs[0] = "changed"
		input.RequiredClaims[0] = "changed"
		if state.roots[root.ID].ExpectedBuilderIDs[0] == "changed" || state.roots[root.ID].RequiredClaims[0] == "changed" {
			t.Fatal("trust policy aliases caller memory")
		}
	}
}
