package awskms

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type readinessKMSClient struct {
	fakeKMSSigner
	describe func(context.Context, *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error)
}

func (c *readinessKMSClient) DescribeKey(ctx context.Context, input *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return c.describe(ctx, input)
}

func TestReadinessChecksEnabledAWSSigningMetadataWithoutSigning(t *testing.T) {
	metadata := &types.KeyMetadata{Enabled: true, KeyState: types.KeyStateEnabled, KeyUsage: types.KeyUsageTypeSignVerify, SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}}
	var providerErr error
	calls := 0
	client := &readinessKMSClient{describe: func(ctx context.Context, input *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
		calls++
		if input.KeyId == nil || *input.KeyId != "alias/required-signer" {
			t.Fatal("readiness used a different key")
		}
		if _, bounded := ctx.Deadline(); !bounded {
			t.Fatal("provider metadata request has no deadline")
		}
		return &kms.DescribeKeyOutput{KeyMetadata: metadata}, providerErr
	}}
	executor, err := NewWithClient(client, Config{KeyID: "alias/required-signer"})
	if err != nil {
		t.Fatal(err)
	}
	check := func(unavailable bool) {
		t.Helper()
		err := executor.CheckReadiness(t.Context())
		if (err != nil) != unavailable || (err != nil && strings.Contains(err.Error(), "private-")) {
			t.Fatalf("unavailable=%v err=%v", unavailable, err)
		}
		if client.input != nil || client.verifyInput != nil {
			t.Fatal("health performed a signing or verification operation")
		}
	}
	check(false)
	providerErr = errors.New("private-provider-credentials")
	check(true)
	providerErr = nil
	check(false)
	metadata.Enabled = false
	check(true)
	metadata.Enabled = true
	metadata.KeyState = types.KeyStatePendingDeletion
	check(true)
	metadata.KeyState = types.KeyStateEnabled
	metadata.KeyUsage = types.KeyUsageTypeEncryptDecrypt
	check(true)
	metadata.KeyUsage = types.KeyUsageTypeSignVerify
	metadata.SigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPssSha256}
	check(true)
	metadata.SigningAlgorithms = []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256}
	check(false)
	metadata = nil
	check(true)
	if calls != 9 {
		t.Fatalf("metadata calls=%d", calls)
	}
}

func TestReadinessAWSFailsClosedOnMissingProbeAndCancellation(t *testing.T) {
	for _, executor := range []*Executor{nil, {}, {client: &fakeKMSSigner{}, keyID: "key"}} {
		if err := executor.CheckReadiness(t.Context()); err == nil {
			t.Fatal("unconfigured metadata check reported healthy")
		}
	}
	client := &readinessKMSClient{describe: func(ctx context.Context, _ *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
		<-ctx.Done()
		return nil, errors.New("private-deadline-details")
	}}
	executor, err := NewWithClient(client, Config{KeyID: "key", Timeout: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.CheckReadiness(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := executor.CheckReadiness(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
