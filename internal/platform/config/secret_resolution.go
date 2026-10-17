package config

import (
	"context"
	"errors"
	"maps"
	"strings"
)

// SecretFileActivation identifies the validated feature owning a file source.
type SecretFileActivation uint8

const (
	SecretFileAlways SecretFileActivation = iota
	SecretFileObjectStore
	SecretFileSigningGateway
	SecretFileProviderGateway
	SecretFileTransparencyGateway
)

var ErrUnresolvedSecretReference = errors.New("secret reference requires explicit resolution")

// PreparedInput owns pure preflight results and reference declarations. It has
// no settings accessor that could pass unresolved credentials into startup.
type PreparedInput struct {
	redactedValue
	role        Role
	environment Environment
	parsed      parsedInput
	references  []secretFileReference
}

// Prepare validates captured input without consulting ambient state or files.
// Only fields backed by a valid file declaration defer value-dependent checks.
func Prepare(environment Environment, role Role) (PreparedInput, error) {
	refs, err := parseSecretReferences(environment, role)
	if err != nil {
		return PreparedInput{}, err
	}
	deferred := make(map[string]bool, len(refs))
	for _, ref := range refs {
		deferred[ref.target] = true
	}
	input, err := parseRoleInputDeferred(environment, role, deferred)
	if err != nil {
		return PreparedInput{}, err
	}
	environment.values = maps.Clone(environment.values)
	return PreparedInput{role: role, environment: environment, parsed: input, references: refs}, nil
}

// Resolve materializes enabled project-owned secret files, then repeats complete
// input validation. Disabled resolution returns zero settings and performs no I/O.
// Native SDK defaults/credential lifecycle and provider startup remain separate.
func Resolve(ctx context.Context, input PreparedInput, enabled bool) (Configuration, error) {
	if input.role != API && input.role != Worker && input.role != Migrate && input.role != CLI {
		return Configuration{}, ErrInvalidRole
	}
	if ctx == nil {
		return Configuration{}, ErrSecretResolution
	}
	if err := ctx.Err(); err != nil {
		return Configuration{}, err
	}
	if !enabled {
		return Configuration{}, nil
	}
	values := maps.Clone(input.environment.values)
	for _, d := range Definitions() {
		if d.FileOption != "" {
			delete(values, d.FileOption)
		}
	}
	remaining := maxEnvironmentBytes
	for _, ref := range input.references {
		if !secretReferenceActive(ref, input.parsed) {
			continue
		}
		secret, err := readSecretFile(ctx, ref.path, min(ref.maxBytes, remaining))
		if err != nil {
			return Configuration{}, err
		}
		remaining -= len(secret.value)
		values[ref.target] = secret.value
	}
	entries := make([]string, 0, len(values))
	for name, value := range values {
		entries = append(entries, name+"="+value)
	}
	environment, err := Capture(entries)
	if err != nil {
		return Configuration{}, ErrSecretResolution
	}
	parsed, err := parseRoleInput(environment, input.role)
	if err != nil {
		return Configuration{}, ErrSecretResolution
	}
	configuration := projectInput(parsed)
	configuration.source = sourceIdentity(input.environment)
	configuration.workerMetricsHash, configuration.workerMetricsEnabled, err = resolveWorkerMetricsSecret(ctx, parsed, remaining)
	if err != nil {
		return Configuration{}, err
	}
	if err := ctx.Err(); err != nil {
		return Configuration{}, err
	}
	return configuration, nil
}

func secretReferenceActive(ref secretFileReference, input parsedInput) bool {
	v := input.values
	switch ref.activation {
	case SecretFileAlways:
		return true
	case SecretFileObjectStore:
		return v["EVYDENCE_OBJECT_STORE"].text == "s3" || v["EVYDENCE_OBJECT_STORE"].text == "minio"
	case SecretFileSigningGateway:
		mode := strings.ReplaceAll(v["EVYDENCE_SIGNING_KEY_MODE"].text, "-", "_")
		return v["EVYDENCE_SIGNING_EXECUTOR_URL"].text != "" && mode != "aws_kms" && mode != "gcp_kms" && mode != "azure_key_vault"
	case SecretFileProviderGateway:
		return v["EVYDENCE_PROVIDER_VALIDATION_GATEWAY_URL"].text != ""
	case SecretFileTransparencyGateway:
		return v["EVYDENCE_TRANSPARENCY_PROOF_GATEWAY_URL"].text != ""
	default:
		return false
	}
}
