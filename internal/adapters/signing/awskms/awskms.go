package awskms

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const defaultTimeout = 10 * time.Second

type Config struct {
	Region           string
	KeyID            string
	Endpoint         string
	SigningAlgorithm string
	Timeout          time.Duration
}

type kmsSigner interface {
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

type Executor struct {
	client    kmsSigner
	keyID     string
	algorithm types.SigningAlgorithmSpec
	timeout   time.Duration
}

func New(ctx context.Context, cfg Config) (*Executor, error) {
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, app.ErrValidation
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(strings.TrimSpace(cfg.Region)))
	if err != nil {
		return nil, errors.New("load AWS KMS signing configuration")
	}
	options := []func(*kms.Options){}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		options = append(options, func(o *kms.Options) {
			o.BaseEndpoint = &endpoint
		})
	}
	return NewWithClient(kms.NewFromConfig(awsCfg, options...), cfg)
}

func NewWithClient(client kmsSigner, cfg Config) (*Executor, error) {
	keyID := strings.TrimSpace(cfg.KeyID)
	if client == nil || keyID == "" {
		return nil, app.ErrValidation
	}
	algorithm, err := parseSigningAlgorithm(cfg.SigningAlgorithm)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Executor{client: client, keyID: keyID, algorithm: algorithm, timeout: timeout}, nil
}

func (e *Executor) Sign(ctx context.Context, request app.SigningRequest) (app.SigningResult, error) {
	if e == nil || e.client == nil || e.keyID == "" {
		return app.SigningResult{}, app.ErrValidation
	}
	if strings.TrimSpace(request.TenantID) == "" || strings.TrimSpace(request.SubjectType) == "" || strings.TrimSpace(request.SubjectID) == "" {
		return app.SigningResult{}, app.ErrValidation
	}
	digest, err := parseSHA256Digest(request.PayloadHash)
	if err != nil {
		return app.SigningResult{}, err
	}
	callCtx := ctx
	var cancel context.CancelFunc
	if e.timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}
	output, err := e.client.Sign(callCtx, &kms.SignInput{
		KeyId:            &e.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: e.algorithm,
	})
	if err != nil {
		return app.SigningResult{}, errors.New("execute AWS KMS signing request")
	}
	if len(output.Signature) == 0 || len(output.Signature) > 32768 {
		return app.SigningResult{}, app.ErrValidation
	}
	keyID := e.keyID
	if output.KeyId != nil && strings.TrimSpace(*output.KeyId) != "" {
		keyID = strings.TrimSpace(*output.KeyId)
	}
	algorithm := output.SigningAlgorithm
	if algorithm == "" {
		algorithm = e.algorithm
	}
	return app.SigningResult{
		Signature: base64.StdEncoding.EncodeToString(output.Signature),
		KeyID:     keyID,
		Algorithm: "aws-kms:" + string(algorithm),
		Checks: []domain.VerifyCheck{
			{Name: "aws_kms_signature_returned", Result: "passed", Detail: "AWS KMS returned a signature over the submitted SHA-256 digest."},
		},
	}, nil
}

func parseSHA256Digest(value string) ([]byte, error) {
	const prefix = "sha256:"
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, prefix) {
		return nil, app.ErrValidation
	}
	encoded := strings.TrimPrefix(trimmed, prefix)
	if len(encoded) != 64 {
		return nil, app.ErrValidation
	}
	digest, err := hex.DecodeString(encoded)
	if err != nil || len(digest) != 32 {
		return nil, app.ErrValidation
	}
	return digest, nil
}

func parseSigningAlgorithm(value string) (types.SigningAlgorithmSpec, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return types.SigningAlgorithmSpecEcdsaSha256, nil
	}
	algorithm := types.SigningAlgorithmSpec(trimmed)
	switch algorithm {
	case types.SigningAlgorithmSpecEcdsaSha256,
		types.SigningAlgorithmSpecRsassaPssSha256,
		types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		return algorithm, nil
	default:
		return "", errors.New("unsupported AWS KMS signing algorithm")
	}
}
