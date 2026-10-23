package awskms

import (
	"context"
	"errors"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aatuh/evydence/internal/app"
)

type kmsMetadataReader interface {
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// CheckReadiness reads only the configured key's operational metadata. It
// requires kms:DescribeKey in addition to the signing path's permissions and
// never creates a signature, receipt, or test evidence. Metadata access does
// not prove Sign permission or availability of every tenant-selected key.
func (e *Executor) CheckReadiness(ctx context.Context) error {
	if e == nil || e.client == nil || e.keyID == "" || ctx == nil {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	reader, ok := e.client.(kmsMetadataReader)
	if !ok {
		return app.ErrValidation
	}
	timeout := e.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, err := reader.DescribeKey(callCtx, &kms.DescribeKeyInput{KeyId: &e.keyID})
	if deadlineErr := callCtx.Err(); deadlineErr != nil {
		return deadlineErr
	}
	if err == nil && output != nil && output.KeyMetadata != nil {
		key := output.KeyMetadata
		if key.Enabled && key.KeyState == types.KeyStateEnabled && key.KeyUsage == types.KeyUsageTypeSignVerify && slices.Contains(key.SigningAlgorithms, e.algorithm) {
			return nil
		}
	}
	return errors.New("AWS KMS signing dependency is unavailable")
}
