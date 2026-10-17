package config

import "maps"

// databaseInput owns each supplied layer and its pre-service candidate. A
// selected service still needs bounded resolution between native and explicit
// values. Defaults, pass/TLS files and connectivity are separate owners.
type databaseInput struct {
	redactedValue
	native       databaseSettings
	explicit     databaseSettings
	candidate    databaseSettings
	needsService bool
}

func parseDatabaseInput(raw string, input nativeInputs) (databaseInput, error) {
	explicit, err := parseDatabaseDSNParts(raw)
	if err != nil {
		return databaseInput{}, err
	}
	native := make(map[string]string)
	for _, d := range NativeDefinitions() {
		if d.Boundary != NativePostgres {
			continue
		}
		if value, exists := input.selected(d); exists {
			native[d.Parameter] = value.raw
		}
	}
	candidate := maps.Clone(native)
	maps.Copy(candidate, explicit.values)
	if len(candidate) > maxDatabaseSettings {
		return databaseInput{}, ErrInvalidValue
	}
	_, needsService := candidate["service"]
	if needsService {
		// A service can replace native values and fill missing explicit values.
		// Contradictions fully specified by the DSN cannot be repaired by it.
		if err := validateDatabaseRelationships(explicit.values, true); err != nil {
			return databaseInput{}, err
		}
	} else if err := validateDatabaseRelationships(candidate, false); err != nil {
		return databaseInput{}, err
	}
	return databaseInput{
		native: databaseSettings{values: native}, explicit: explicit,
		candidate: databaseSettings{values: candidate}, needsService: needsService,
	}, nil
}
