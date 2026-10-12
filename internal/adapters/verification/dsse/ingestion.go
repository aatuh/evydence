package dsse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"

	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

const buildAttestationIngestionLimit = int64(20 << 20)

// BuildAttestationIngestionParser validates the observed size/digest and the
// existing structural DSSE/in-toto profile. It never assigns signature trust;
// verification remains a separate policy-bound operation.
type BuildAttestationIngestionParser struct{}

var _ releaseapp.BuildAttestationParser = BuildAttestationIngestionParser{}

func (BuildAttestationIngestionParser) ParseBuildAttestation(ctx context.Context, source releaseapp.BuildAttestationPayloadSource) (releaseapp.ParsedBuildAttestation, error) {
	if ctx == nil {
		return releaseapp.ParsedBuildAttestation{}, releaseapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return releaseapp.ParsedBuildAttestation{}, err
	}
	if source.Open == nil || source.Size <= 0 || source.Size > buildAttestationIngestionLimit || len(source.Digest) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(source.Digest, "sha256:") {
		return releaseapp.ParsedBuildAttestation{}, releaseapp.ErrValidation
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(source.Digest, "sha256:")); err != nil {
		return releaseapp.ParsedBuildAttestation{}, releaseapp.ErrValidation
	}
	reader, err := source.Open()
	if err != nil {
		return releaseapp.ParsedBuildAttestation{}, err
	}
	if reader == nil {
		return releaseapp.ParsedBuildAttestation{}, releaseapp.ErrValidation
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, buildAttestationIngestionLimit+1))
	if err != nil {
		return releaseapp.ParsedBuildAttestation{}, err
	}
	if err := ctx.Err(); err != nil {
		return releaseapp.ParsedBuildAttestation{}, err
	}
	sum := sha256.Sum256(raw)
	if int64(len(raw)) != source.Size || "sha256:"+hex.EncodeToString(sum[:]) != source.Digest {
		return releaseapp.ParsedBuildAttestation{}, releaseapp.ErrValidation
	}
	parsed, err := Parse(raw)
	if err != nil {
		return releaseapp.ParsedBuildAttestation{}, releaseapp.ErrValidation
	}
	return releaseapp.ParsedBuildAttestation{
		PayloadHash: source.Digest, PayloadSize: source.Size, ParserVersion: releaseapp.BuildAttestationParserVersion,
		PayloadType: parsed.PayloadType, PredicateType: parsed.PredicateType,
		SubjectDigests: append([]string(nil), parsed.SubjectDigests...), BuilderID: parsed.BuilderID,
		BuildType: parsed.BuildType, MaterialsCount: parsed.MaterialsCount, SignatureCount: parsed.SignatureCount,
	}, nil
}
