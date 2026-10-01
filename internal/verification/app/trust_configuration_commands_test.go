package app

import (
	"errors"
	"strings"
	"testing"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

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
