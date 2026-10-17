package config

import "slices"

type Role uint8

const (
	API Role = 1 << iota
	Worker
	Migrate
	CLI
	AllRoles = API | Worker | Migrate | CLI
)

type Kind string

type EndpointPolicy string

const (
	TLSBaseEndpoint          EndpointPolicy = "tls-base"
	GatewayEndpoint          EndpointPolicy = "gateway"
	GatewayReadinessEndpoint EndpointPolicy = "gateway-readiness"
	APIClientEndpoint        EndpointPolicy = "api-client"
	NativeIdentityEndpoint   EndpointPolicy = "native-identity"
	NativeProxyEndpoint      EndpointPolicy = "native-proxy"
)

const (
	Text         Kind = "text"
	Boolean      Kind = "boolean"
	Integer      Kind = "integer"
	Seconds      Kind = "seconds"
	Duration     Kind = "duration"
	Choice       Kind = "choice"
	CIDRs        Kind = "cidrs"
	URL          Kind = "url"
	Path         Kind = "path"
	Base64       Kind = "base64"
	Timestamp    Kind = "timestamp"
	S3BucketName Kind = "s3-bucket-name"
	PostgresDSN  Kind = "postgres-dsn"
)

// Definition contains code-owned metadata, never resolved operator values.
// Zero numeric bounds are meaningful for numeric kinds, not string lengths.
// DefaultPolicy describes a conditional/dynamic default rather than a literal.
type Definition struct {
	Name              string
	Kind              Kind
	EndpointPolicy    EndpointPolicy
	LocalhostOverride string
	// PreserveWhitespace keeps explicit blank input for field validation rather
	// than replacing it with a default. Raw capture is always lossless.
	PreserveWhitespace   bool
	Default              string
	DefaultPolicy        string
	ProductionDefault    string
	NonProductionDefault string
	DefaultWhenSet       string
	ConditionalDefault   string
	Roles                Role
	Required             Role
	ProductionRequired   Role
	Secret               bool
	// FileOption is the schema-owned private-file alternative for a project
	// secret. It declares a reference; it does not perform file resolution.
	FileOption string
	// FileActivation selects the validated feature that may read this alternative.
	FileActivation        SecretFileActivation
	ForbiddenInProduction bool
	Min                   int64
	Max                   int64
	// MaxBytes bounds raw input, or decoded bytes for Base64; zero uses the
	// capture byte limit. MaxItems bounds CIDR/native list entries before allocation.
	MaxBytes          int
	MaxItems          int
	Allowed           []string
	ProductionAllowed []string
	Aliases           []string
	Description       string
}

// Definitions returns sorted, owned metadata for parsing and artifact generation.
// Schema metadata does not itself validate or adopt configuration in commands.
func Definitions() []Definition {
	result := slices.Clone(optionDefinitions)
	for i := range result {
		result[i].Allowed = slices.Clone(result[i].Allowed)
		result[i].ProductionAllowed = slices.Clone(result[i].ProductionAllowed)
		result[i].Aliases = slices.Clone(result[i].Aliases)
	}
	slices.SortFunc(result, func(a, b Definition) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return result
}
