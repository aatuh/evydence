package awskms

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aatuh/evydence/internal/app"
)

type fakeKMSSigner struct {
	input *kms.SignInput
	err   error
}

func (f *fakeKMSSigner) Sign(_ context.Context, input *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.input = input
	if f.err != nil {
		return nil, f.err
	}
	keyID := "arn:aws:kms:eu-north-1:111122223333:key/test"
	return &kms.SignOutput{
		KeyId:            &keyID,
		Signature:        []byte("der-signature"),
		SigningAlgorithm: input.SigningAlgorithm,
	}, nil
}

func TestNewWithClientRequiresClientAndKeyID(t *testing.T) {
	if _, err := NewWithClient(nil, Config{KeyID: "key"}); err == nil {
		t.Fatal("expected nil client to be rejected")
	}
	if _, err := NewWithClient(&fakeKMSSigner{}, Config{}); err == nil {
		t.Fatal("expected missing key id to be rejected")
	}
}

func TestNewWithClientRejectsNonSHA256Algorithms(t *testing.T) {
	if _, err := NewWithClient(&fakeKMSSigner{}, Config{KeyID: "key", SigningAlgorithm: string(types.SigningAlgorithmSpecEcdsaSha384)}); err == nil {
		t.Fatal("expected SHA-384 algorithm to be rejected for sha256 payload hashes")
	}
}

func TestSignSendsDigestOnlyAndReturnsBase64Signature(t *testing.T) {
	fake := &fakeKMSSigner{}
	executor, err := NewWithClient(fake, Config{KeyID: "alias/evydence-release", SigningAlgorithm: string(types.SigningAlgorithmSpecRsassaPssSha256)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Sign(t.Context(), app.SigningRequest{
		TenantID:    "ten_1",
		SubjectType: "release",
		SubjectID:   "rel_1",
		PayloadHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fake.input == nil {
		t.Fatal("expected KMS request")
	}
	if fake.input.KeyId == nil || *fake.input.KeyId != "alias/evydence-release" {
		t.Fatalf("key id = %v", fake.input.KeyId)
	}
	if fake.input.MessageType != types.MessageTypeDigest {
		t.Fatalf("message type = %q, want DIGEST", fake.input.MessageType)
	}
	if got := len(fake.input.Message); got != 32 {
		t.Fatalf("message length = %d, want SHA-256 digest length", got)
	}
	if fake.input.SigningAlgorithm != types.SigningAlgorithmSpecRsassaPssSha256 {
		t.Fatalf("algorithm = %q", fake.input.SigningAlgorithm)
	}
	if result.Signature != base64.StdEncoding.EncodeToString([]byte("der-signature")) {
		t.Fatalf("signature = %q", result.Signature)
	}
	if result.Algorithm != "aws-kms:RSASSA_PSS_SHA_256" {
		t.Fatalf("algorithm = %q", result.Algorithm)
	}
	if result.KeyID == "" || len(result.Checks) != 1 || result.Checks[0].Name != "aws_kms_signature_returned" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSignRejectsMalformedDigest(t *testing.T) {
	executor, err := NewWithClient(&fakeKMSSigner{}, Config{KeyID: "alias/evydence-release"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Sign(t.Context(), app.SigningRequest{TenantID: "ten_1", SubjectType: "release", SubjectID: "rel_1", PayloadHash: "sha256:not-hex"}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("err=%v, want validation", err)
	}
}

func TestSignHidesProviderErrorDetails(t *testing.T) {
	fake := &fakeKMSSigner{err: errors.New("provider included payload sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")}
	executor, err := NewWithClient(fake, Config{KeyID: "alias/evydence-release"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.Sign(context.Background(), app.SigningRequest{
		TenantID:    "ten_1",
		SubjectType: "release",
		SubjectID:   "rel_1",
		PayloadHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err == nil {
		t.Fatal("expected provider error")
	}
	if strings.Contains(err.Error(), "0123456789abcdef") || strings.Contains(err.Error(), "payload") {
		t.Fatalf("error leaked provider details: %v", err)
	}
}
