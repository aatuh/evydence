package config

import "time"

// CLISettings is a value copy. Slice accessors return owned copies.
// Formatting and JSON redact the entire settings value.
type CLISettings struct {
	redactedValue
	CI                bool       `env:"CI"`
	APIKey            Secret     `env:"EVYDENCE_API_KEY"`
	APIURL            string     `env:"EVYDENCE_API_URL"`
	ArtifactID        string     `env:"EVYDENCE_ARTIFACT_ID"`
	BuildFinishedAt   time.Time  `env:"EVYDENCE_BUILD_FINISHED_AT"`
	BuildStartedAt    time.Time  `env:"EVYDENCE_BUILD_STARTED_AT"`
	BuildStatus       string     `env:"EVYDENCE_BUILD_STATUS"`
	GitHubOIDCSubject string     `env:"EVYDENCE_GITHUB_OIDC_SUBJECT"`
	ProductID         string     `env:"EVYDENCE_PRODUCT_ID"`
	ProjectID         string     `env:"EVYDENCE_PROJECT_ID"`
	ReleaseID         string     `env:"EVYDENCE_RELEASE_ID"`
	GitHubActor       string     `env:"GITHUB_ACTOR"`
	GitHubJob         string     `env:"GITHUB_JOB"`
	GitHubRef         string     `env:"GITHUB_REF"`
	GitHubRepository  string     `env:"GITHUB_REPOSITORY"`
	GitHubRunAttempt  RunAttempt `env:"GITHUB_RUN_ATTEMPT"`
	GitHubRunID       string     `env:"GITHUB_RUN_ID"`
	GitHubSHA         string     `env:"GITHUB_SHA"`
	GitHubWorkflowRef string     `env:"GITHUB_WORKFLOW_REF"`
}

// RunAttempt retains the validated number and the trimmed operator spelling.
// Existing build idempotency keys include that spelling (for example, "02").
// Numeric payloads must not silently change a valid existing request's key.
type RunAttempt struct {
	redactedValue
	number   int64
	identity string
}

func (r RunAttempt) Number() int64    { return r.number }
func (r RunAttempt) Identity() string { return r.identity }
