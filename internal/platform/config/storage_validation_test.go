package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestStorageConfigurationRejectsMalformedOrIncompleteInput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
		want  error
	}{
		{"missing-s3-endpoint", []string{"EVYDENCE_OBJECT_STORE=s3"}, ErrMissingValue},
		{"missing-minio-bucket", []string{"EVYDENCE_OBJECT_STORE=minio", "EVYDENCE_S3_ENDPOINT=localhost:9000", "EVYDENCE_S3_ACCESS_KEY_ID=PRIVATE_ID", "EVYDENCE_S3_SECRET_ACCESS_KEY=PRIVATE_KEY"}, ErrMissingValue},
		{"missing-s3-credentials", []string{"EVYDENCE_OBJECT_STORE=s3", "EVYDENCE_S3_ENDPOINT=localhost:9000", "EVYDENCE_S3_BUCKET=evidence"}, ErrMissingValue},
		{"scheme", []string{"EVYDENCE_S3_ENDPOINT=https://PRIVATE_STORAGE.invalid"}, ErrInvalidValue},
		{"path", []string{"EVYDENCE_S3_ENDPOINT=localhost:9000/PRIVATE_BUCKET"}, ErrInvalidValue},
		{"userinfo", []string{"EVYDENCE_S3_ENDPOINT=PRIVATE_USER:PRIVATE_KEY@localhost:9000"}, ErrInvalidValue},
		{"query", []string{"EVYDENCE_S3_ENDPOINT=localhost:9000?PRIVATE_QUERY=1"}, ErrInvalidValue},
		{"bad-port", []string{"EVYDENCE_S3_ENDPOINT=localhost:65536"}, ErrInvalidValue},
		{"zero-port", []string{"EVYDENCE_S3_ENDPOINT=localhost:0"}, ErrInvalidValue},
		{"invalid-region", []string{"EVYDENCE_S3_REGION=PRIVATE REGION"}, ErrInvalidValue},
		{"region-too-long", []string{"EVYDENCE_S3_REGION=" + strings.Repeat("a", 64)}, ErrInvalidValue},
		{"invalid-bucket", []string{"EVYDENCE_S3_BUCKET=PRIVATE/BUCKET"}, ErrInvalidValue},
		{"short-bucket", []string{"EVYDENCE_S3_BUCKET=ab"}, ErrInvalidValue},
		{"long-bucket", []string{"EVYDENCE_S3_BUCKET=" + strings.Repeat("a", 64)}, ErrInvalidValue},
		{"ip-bucket", []string{"EVYDENCE_S3_BUCKET=127.0.0.1"}, ErrInvalidValue},
		{"public-cleartext", []string{"EVYDENCE_S3_ENDPOINT=objects.example.invalid:9000"}, ErrInvalidValue},
		{"public-ipv6-cleartext", []string{"EVYDENCE_S3_ENDPOINT=[2606:4700:4700::1111]:9000"}, ErrInvalidValue},
		{"invalid-ipv6-brackets", []string{"EVYDENCE_S3_ENDPOINT=[PRIVATE_HOST]:9000"}, ErrInvalidValue},
		{"unbracketed-ipv6", []string{"EVYDENCE_S3_ENDPOINT=2606:4700:4700::1111"}, ErrInvalidValue},
		{"invalid-sdk-domain", []string{"EVYDENCE_S3_ENDPOINT=-PRIVATE_STORAGE:9000"}, ErrInvalidValue},
		{"aws-cleartext", []string{"EVYDENCE_S3_ENDPOINT=s3.us-east-1.amazonaws.com", "EVYDENCE_S3_REGION=us-east-1"}, ErrInvalidValue},
		{"aws-region-missing", []string{"EVYDENCE_S3_ENDPOINT=s3.us-east-1.amazonaws.com", "EVYDENCE_S3_USE_SSL=true"}, ErrInvalidValue},
	} {
		for _, role := range []Role{API, Worker} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, role), func(t *testing.T) {
				input, err := parseRoleInput(roleEnvironment(t, role, false, tc.extra...), role)
				if !errors.Is(err, tc.want) || !reflect.DeepEqual(input, parsedInput{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
					t.Fatal("invalid storage configuration returned values or disclosed input", err)
				}
			})
		}
	}
}

func TestStorageConfigurationAcceptsOwnedInputsWithoutIO(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:1", "minio:9000", "10.0.0.8:9000", "minio.default.svc:9000", "[::1]:9000", "[fd00::1]:9000"} {
		input, err := parseRoleInput(roleEnvironment(t, Worker, false,
			"EVYDENCE_OBJECT_STORE=minio", "EVYDENCE_S3_ENDPOINT="+endpoint,
			"EVYDENCE_S3_BUCKET=PRIVATE_NONEXISTENT_BUCKET", "EVYDENCE_S3_ACCESS_KEY_ID= PRIVATE_ID ", "EVYDENCE_S3_SECRET_ACCESS_KEY= PRIVATE_KEY ",
		), Worker)
		if err != nil {
			t.Fatal("storage validation contacted a service or rejected a private endpoint", err)
		}
		s := projectInput(input).Storage()
		if s.S3Endpoint != endpoint || s.S3AccessKeyID.Reveal() != " PRIVATE_ID " || s.S3SecretAccessKey.Reveal() != " PRIVATE_KEY " {
			t.Fatal("validated storage input changed credential bytes or endpoint")
		}
	}
	if _, err := parseRoleInput(roleEnvironment(t, API, false, "EVYDENCE_S3_ENDPOINT=objects.example.invalid:9000", "EVYDENCE_S3_USE_SSL=true"), API); err != nil {
		t.Fatal("inactive TLS endpoint acquired unrelated required credentials", err)
	}
	if _, err := parseRoleInput(roleEnvironment(t, Migrate, false, "EVYDENCE_S3_ENDPOINT=PRIVATE_UNUSED"), Migrate); err != nil {
		t.Fatal("migration role acquired storage configuration", err)
	}
}

func TestStorageBucketGrammarAndDiagnosticsMatchPinnedSDK(t *testing.T) {
	for _, raw := range []string{"abc", "LEGACY_BUCKET", strings.Repeat("a", 63), " padded-bucket "} {
		got, err := ParseS3BucketName(raw)
		if err != nil || got != strings.TrimSpace(raw) {
			t.Fatal("supported SDK bucket grammar or trimming changed", err)
		}
	}
	for _, raw := range []string{"", "ab", strings.Repeat("a", 64), "127.0.0.1", "PRIVATE/BUCKET", "PRIVATE..BUCKET"} {
		got, err := ParseS3BucketName(raw)
		if !errors.Is(err, ErrInvalidValue) || got != "" || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("invalid SDK bucket grammar returned input or unsafe diagnostics", err)
		}
	}
}
