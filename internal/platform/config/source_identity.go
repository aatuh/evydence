package config

// SourceIdentity owns a private digest only. It retains no raw input values,
// credential references or mutable storage; formatting and JSON are redacted.
type SourceIdentity struct {
	redactedValue
	fingerprint [32]byte
	captured    bool
}

// MatchesSource compares bounded captured input with the original source. Secret
// materialization preserves the declaration's identity rather than its contents.
func (s SourceIdentity) MatchesSource(environment Environment) bool {
	return s.captured && environment.values != nil && s.fingerprint == environment.fingerprint
}

func sourceIdentity(environment Environment) SourceIdentity {
	return SourceIdentity{fingerprint: environment.fingerprint, captured: environment.values != nil}
}
