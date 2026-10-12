// Package dsse verifies the narrowly supported offline DSSE/in-toto profile.
// It deliberately makes no network requests: every trusted verification key
// and policy input must be provided by the caller.
package dsse

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	slsaprovenance "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	securedsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	PayloadTypeInTotoJSON       = "application/vnd.in-toto+json"
	PredicateTypeSLSAProvenance = "https://slsa.dev/provenance/v1"

	CheckPassed      = "passed"
	CheckFailed      = "failed"
	CheckNotVerified = "not_verified"
)

var (
	ErrInvalidEnvelope  = errors.New("invalid DSSE envelope")
	ErrInvalidStatement = errors.New("invalid in-toto statement")
	ErrInvalidPolicy    = errors.New("invalid DSSE verification policy")
)

// TrustRoot is public key material and the root identity supplied by the
// tenant's policy. Certificate chains are intentionally not accepted by this
// profile; callers must use an explicitly configured Ed25519 public key.
type TrustRoot struct {
	ID        string
	KeyID     string
	Algorithm string
	PublicKey string // standard base64 encoded Ed25519 public key
}

// Policy contains every non-secret input required to make an offline decision.
// Empty policy lists are invalid at the application boundary and never imply a
// wildcard trust decision.
type Policy struct {
	Roots                  []TrustRoot
	AllowedPredicateTypes  []string
	ExpectedBuilderIDs     []string
	RequiredClaims         []string
	ExpectedSubjectDigests []string
}

type Check struct {
	Name   string
	Result string
	Detail string
}

// Result is safe receipt content: it retains identifiers and digests, but
// deliberately never copies the raw envelope, signature, or public-key bytes.
type Result struct {
	PayloadType     string
	PredicateType   string
	SubjectDigests  []string
	BuilderID       string
	BuildType       string
	MaterialsCount  int
	SignatureCount  int
	AcceptedRootIDs []string
	Checks          []Check
}

func (r Result) Check(name string) string {
	for _, check := range r.Checks {
		if check.Name == name {
			return check.Result
		}
	}
	return ""
}

// Passed is true only when every profile check was evaluated and passed.
func (r Result) Passed() bool {
	if len(r.Checks) == 0 {
		return false
	}
	for _, check := range r.Checks {
		if check.Result != CheckPassed {
			return false
		}
	}
	return true
}

// Verify parses a DSSE envelope using securesystemslib, verifies its PAE over
// the envelope payload with configured Ed25519 roots, and parses the signed
// in-toto Statement v1 with the maintained in-toto protobuf model.
func Verify(ctx context.Context, raw []byte, policy Policy) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	envelope, statement, result, err := inspect(raw)
	if err != nil {
		return Result{}, err
	}
	if err := validatePolicy(policy); err != nil {
		return Result{}, err
	}

	result.Checks = append(result.Checks, signatureChecks(ctx, envelope, policy.Roots, &result)...)
	if result.PayloadType == PayloadTypeInTotoJSON {
		result.Checks = append(result.Checks, Check{Name: "payload_type", Result: CheckPassed, Detail: result.PayloadType})
	} else {
		result.Checks = append(result.Checks, Check{Name: "payload_type", Result: CheckNotVerified, Detail: result.PayloadType})
	}

	if !contains(policy.AllowedPredicateTypes, result.PredicateType) || result.PredicateType != PredicateTypeSLSAProvenance {
		result.Checks = append(result.Checks,
			Check{Name: "predicate_type", Result: CheckNotVerified, Detail: result.PredicateType},
			Check{Name: "subject_digest", Result: CheckNotVerified},
			Check{Name: "builder_identity", Result: CheckNotVerified},
			Check{Name: "policy_required_claims", Result: CheckNotVerified},
		)
		return result, nil
	}
	result.Checks = append(result.Checks, Check{Name: "predicate_type", Result: CheckPassed, Detail: result.PredicateType})

	provenance, err := parseSLSAProvenance(statement)
	if err != nil {
		return Result{}, err
	}
	result.BuilderID = strings.TrimSpace(provenance.GetRunDetails().GetBuilder().GetId())
	result.BuildType = strings.TrimSpace(provenance.GetBuildDefinition().GetBuildType())
	result.MaterialsCount = len(provenance.GetBuildDefinition().GetResolvedDependencies())

	if subjectsMatch(result.SubjectDigests, policy.ExpectedSubjectDigests) {
		result.Checks = append(result.Checks, Check{Name: "subject_digest", Result: CheckPassed})
	} else {
		result.Checks = append(result.Checks, Check{Name: "subject_digest", Result: CheckFailed})
	}
	if contains(policy.ExpectedBuilderIDs, result.BuilderID) {
		result.Checks = append(result.Checks, Check{Name: "builder_identity", Result: CheckPassed, Detail: result.BuilderID})
	} else {
		result.Checks = append(result.Checks, Check{Name: "builder_identity", Result: CheckFailed, Detail: result.BuilderID})
	}
	if requiredClaimsPresent(provenance, policy.RequiredClaims) {
		result.Checks = append(result.Checks, Check{Name: "policy_required_claims", Result: CheckPassed, Detail: strings.Join(normalized(policy.RequiredClaims), ",")})
	} else {
		result.Checks = append(result.Checks, Check{Name: "policy_required_claims", Result: CheckFailed, Detail: strings.Join(normalized(policy.RequiredClaims), ",")})
	}
	return result, nil
}

// Parse validates the strictly supported DSSE envelope and in-toto Statement
// structure without assigning trust. It is used at upload time to preserve raw
// bytes and bind the claimed subjects to an existing build before verification.
func Parse(raw []byte) (Result, error) {
	_, _, result, err := inspect(raw)
	return result, err
}

func inspect(raw []byte) (*securedsse.Envelope, *intoto.Statement, Result, error) {
	envelope, err := parseEnvelope(raw)
	if err != nil {
		return nil, nil, Result{}, err
	}
	payload, err := envelope.DecodeB64Payload()
	if err != nil {
		return nil, nil, Result{}, fmt.Errorf("%w: decode payload", ErrInvalidEnvelope)
	}
	statement, err := parseStatement(payload)
	if err != nil {
		return nil, nil, Result{}, err
	}
	result := Result{
		PayloadType:    strings.TrimSpace(envelope.PayloadType),
		PredicateType:  strings.TrimSpace(statement.GetPredicateType()),
		SubjectDigests: statementDigests(statement),
		SignatureCount: len(envelope.Signatures),
	}
	if result.PredicateType == PredicateTypeSLSAProvenance {
		provenance, err := parseSLSAProvenance(statement)
		if err != nil {
			return nil, nil, Result{}, err
		}
		result.BuilderID = strings.TrimSpace(provenance.GetRunDetails().GetBuilder().GetId())
		result.BuildType = strings.TrimSpace(provenance.GetBuildDefinition().GetBuildType())
		result.MaterialsCount = len(provenance.GetBuildDefinition().GetResolvedDependencies())
	}
	return envelope, statement, result, nil
}

func parseEnvelope(raw []byte) (*securedsse.Envelope, error) {
	var envelope securedsse.Envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, ErrInvalidEnvelope
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		return nil, ErrInvalidEnvelope
	} else if !errors.Is(err, io.EOF) {
		return nil, ErrInvalidEnvelope
	}
	if strings.TrimSpace(envelope.PayloadType) == "" || strings.TrimSpace(envelope.Payload) == "" || len(envelope.Signatures) == 0 {
		return nil, ErrInvalidEnvelope
	}
	for _, signature := range envelope.Signatures {
		if strings.TrimSpace(signature.Sig) == "" {
			return nil, ErrInvalidEnvelope
		}
	}
	return &envelope, nil
}

func parseStatement(payload []byte) (*intoto.Statement, error) {
	statement := &intoto.Statement{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, statement); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	if err := statement.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	if statement.GetType() != intoto.StatementTypeUri {
		return nil, ErrInvalidStatement
	}
	if len(statementDigests(statement)) == 0 {
		return nil, ErrInvalidStatement
	}
	return statement, nil
}

func parseSLSAProvenance(statement *intoto.Statement) (*slsaprovenance.Provenance, error) {
	predicate, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("%w: encode SLSA predicate: %w", ErrInvalidStatement, err)
	}
	provenance := &slsaprovenance.Provenance{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(predicate, provenance); err != nil {
		return nil, fmt.Errorf("%w: decode SLSA predicate: %w", ErrInvalidStatement, err)
	}
	if err := provenance.Validate(); err != nil {
		return nil, fmt.Errorf("%w: validate SLSA predicate: %w", ErrInvalidStatement, err)
	}
	return provenance, nil
}

func signatureChecks(ctx context.Context, envelope *securedsse.Envelope, roots []TrustRoot, result *Result) []Check {
	verifiers := make([]securedsse.Verifier, 0, len(roots))
	rootIDs := make(map[string]string, len(roots))
	for _, root := range roots {
		publicKey, err := base64.StdEncoding.DecodeString(root.PublicKey)
		if err != nil {
			continue
		}
		verifier, err := signerverifier.NewED25519SignerVerifierFromSSLibKey(&signerverifier.SSLibKey{
			KeyID:   root.KeyID,
			KeyType: signerverifier.ED25519KeyType,
			Scheme:  "ed25519",
			KeyVal:  signerverifier.KeyVal{Public: hex.EncodeToString(publicKey)},
		})
		if err != nil {
			continue
		}
		verifiers = append(verifiers, verifier)
		rootIDs[root.KeyID] = root.ID
	}
	if len(verifiers) == 0 {
		return []Check{{Name: "dsse_pae_signature", Result: CheckNotVerified}, {Name: "trusted_root", Result: CheckNotVerified}}
	}
	verifier, err := securedsse.NewEnvelopeVerifier(verifiers...)
	if err != nil {
		return []Check{{Name: "dsse_pae_signature", Result: CheckNotVerified}, {Name: "trusted_root", Result: CheckNotVerified}}
	}
	accepted, _, err := verifier.VerifyAndDecode(ctx, envelope)
	if err != nil || len(accepted) == 0 {
		return []Check{{Name: "dsse_pae_signature", Result: CheckFailed}, {Name: "trusted_root", Result: CheckFailed}}
	}
	for _, acceptedKey := range accepted {
		if rootID := rootIDs[acceptedKey.KeyID]; rootID != "" {
			result.AcceptedRootIDs = append(result.AcceptedRootIDs, rootID)
		}
	}
	result.AcceptedRootIDs = normalized(result.AcceptedRootIDs)
	return []Check{{Name: "dsse_pae_signature", Result: CheckPassed}, {Name: "trusted_root", Result: CheckPassed, Detail: strings.Join(result.AcceptedRootIDs, ",")}}
}

func validatePolicy(policy Policy) error {
	if len(policy.Roots) == 0 || len(policy.AllowedPredicateTypes) == 0 || len(policy.ExpectedBuilderIDs) == 0 || len(policy.RequiredClaims) == 0 {
		return ErrInvalidPolicy
	}
	for _, root := range policy.Roots {
		publicKey, err := base64.StdEncoding.DecodeString(root.PublicKey)
		if strings.TrimSpace(root.ID) == "" || strings.TrimSpace(root.KeyID) == "" || root.Algorithm != "Ed25519" || err != nil || len(publicKey) != 32 {
			return ErrInvalidPolicy
		}
	}
	for _, claim := range normalized(policy.RequiredClaims) {
		switch claim {
		case "builder_id", "build_type", "external_parameters":
		default:
			return ErrInvalidPolicy
		}
	}
	return nil
}

func statementDigests(statement *intoto.Statement) []string {
	digests := []string{}
	for _, subject := range statement.GetSubject() {
		value := strings.ToLower(strings.TrimSpace(subject.GetDigest()["sha256"]))
		if len(value) != 64 {
			continue
		}
		if _, err := hex.DecodeString(value); err != nil {
			continue
		}
		digests = append(digests, "sha256:"+value)
	}
	return normalized(digests)
}

func subjectsMatch(subjects, expected []string) bool {
	if len(subjects) == 0 || len(expected) == 0 {
		return false
	}
	allowed := make(map[string]struct{}, len(expected))
	for _, digest := range normalized(expected) {
		allowed[digest] = struct{}{}
	}
	for _, digest := range subjects {
		if _, ok := allowed[digest]; !ok {
			return false
		}
	}
	return true
}

func requiredClaimsPresent(provenance *slsaprovenance.Provenance, claims []string) bool {
	for _, claim := range normalized(claims) {
		switch claim {
		case "builder_id":
			if strings.TrimSpace(provenance.GetRunDetails().GetBuilder().GetId()) == "" {
				return false
			}
		case "build_type":
			if strings.TrimSpace(provenance.GetBuildDefinition().GetBuildType()) == "" {
				return false
			}
		case "external_parameters":
			if provenance.GetBuildDefinition().GetExternalParameters() == nil {
				return false
			}
		}
	}
	return true
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func normalized(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
