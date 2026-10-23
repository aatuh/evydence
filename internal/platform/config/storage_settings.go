package config

// StorageSettings is a value copy. Slice accessors return owned copies.
// Formatting and JSON redact the entire settings value.
type StorageSettings struct {
	redactedValue
	Directory         string `env:"EVYDENCE_OBJECT_DIR"`
	Kind              string `env:"EVYDENCE_OBJECT_STORE"`
	S3AccessKeyID     Secret `env:"EVYDENCE_S3_ACCESS_KEY_ID"`
	S3Bucket          string `env:"EVYDENCE_S3_BUCKET"`
	S3Endpoint        string `env:"EVYDENCE_S3_ENDPOINT"`
	S3Region          string `env:"EVYDENCE_S3_REGION"`
	S3SecretAccessKey Secret `env:"EVYDENCE_S3_SECRET_ACCESS_KEY"`
	S3UseSSL          bool   `env:"EVYDENCE_S3_USE_SSL"`
}
