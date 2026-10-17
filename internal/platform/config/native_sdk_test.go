package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

func TestNativeSDKCatalogueCoversReviewedInputs(t *testing.T) {
	// Reviewed against the pinned configuration/credential loaders, including
	// AWS's computed service endpoints and Azure's transitive MSAL reads.
	expected := map[NativeBoundary]string{
		NativeAWS:    `AWS_ACCESS_KEY_ID AWS_ACCESS_KEY AWS_SECRET_ACCESS_KEY AWS_SECRET_KEY AWS_SESSION_TOKEN AWS_ACCOUNT_ID AWS_ACCOUNT_ID_ENDPOINT_MODE AWS_AUTH_SCHEME_PREFERENCE AWS_CA_BUNDLE AWS_CONFIG_FILE AWS_CONTAINER_AUTHORIZATION_TOKEN AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_DEFAULTS_MODE AWS_PROFILE AWS_DEFAULT_PROFILE AWS_REGION AWS_DEFAULT_REGION AWS_DISABLE_REQUEST_COMPRESSION AWS_EC2_METADATA_DISABLED AWS_EC2_METADATA_SERVICE_ENDPOINT AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE AWS_EC2_METADATA_V1_DISABLED AWS_ENABLE_ENDPOINT_DISCOVERY AWS_ENDPOINT_URL AWS_EXECUTION_ENV AWS_IGNORE_CONFIGURED_ENDPOINT_URLS AWS_LOGIN_CACHE_DIRECTORY AWS_MAX_ATTEMPTS AWS_REQUEST_CHECKSUM_CALCULATION AWS_REQUEST_MIN_COMPRESSION_SIZE_BYTES AWS_RESPONSE_CHECKSUM_VALIDATION AWS_RESTRICT_FILE_PERMISSIONS AWS_RETRY_MODE AWS_ROLE_ARN AWS_ROLE_SESSION_NAME AWS_S3_DISABLE_EXPRESS_SESSION_AUTH AWS_S3_DISABLE_MULTIREGION_ACCESS_POINTS AWS_S3_USE_ARN_REGION AWS_SDK_UA_APP_ID AWS_SHARED_CREDENTIALS_FILE AWS_USE_DUALSTACK_ENDPOINT AWS_USE_FIPS_ENDPOINT AWS_WEB_IDENTITY_TOKEN_FILE AWS_ENDPOINT_URL_KMS AWS_ENDPOINT_URL_STS AWS_ENDPOINT_URL_SSO AWS_ENDPOINT_URL_SSO_OIDC AWS_ENDPOINT_URL_SIGNIN`,
		NativeGoogle: `GOOGLE_APPLICATION_CREDENTIALS GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES GCE_METADATA_HOST`,
		NativeAzure:  `AZURE_ADDITIONALLY_ALLOWED_TENANTS AZURE_AUTHORITY_HOST AZURE_CLIENT_CERTIFICATE_PASSWORD AZURE_CLIENT_CERTIFICATE_PATH AZURE_CLIENT_ID AZURE_CLIENT_SECRET AZURE_CLIENT_SEND_CERTIFICATE_CHAIN AZURE_FEDERATED_TOKEN_FILE AZURE_PASSWORD AZURE_REGIONAL_AUTHORITY_NAME AZURE_TENANT_ID AZURE_TOKEN_CREDENTIALS AZURE_USERNAME IDENTITY_ENDPOINT IDENTITY_HEADER IDENTITY_SERVER_THUMBPRINT MSI_ENDPOINT MSI_SECRET IMDS_ENDPOINT DEFAULT_IDENTITY_CLIENT_ID`,
		NativeHost:   `HOME USERPROFILE APPDATA ProgramData PATH PATHEXT NoDefaultCurrentDirectoryInExePath SYSTEMROOT HTTP_PROXY http_proxy HTTPS_PROXY https_proxy NO_PROXY no_proxy REQUEST_METHOD SSL_CERT_FILE SSL_CERT_DIR`,
	}
	actual := make(map[NativeBoundary][]string)
	seen := make(map[string]bool)
	for _, d := range NativeDefinitions() {
		if d.Name == "" || d.Parameter == "" || d.Source == "" || d.DefaultPolicy == "" || d.MaxBytes <= 0 || d.Roles == 0 || d.Roles&^AllRoles != 0 {
			t.Fatal("incomplete native schema metadata", d.Name)
		}
		for _, name := range append([]string{d.Name}, d.Fallbacks...) {
			if seen[name] || !validEnvironmentName(name) || !selectedEnvironmentName(name) {
				t.Fatal("native name is ambiguous or absent from capture", name)
			}
			seen[name] = true
			if d.Boundary != NativePostgres {
				actual[d.Boundary] = append(actual[d.Boundary], name)
			}
		}
	}
	for boundary, names := range expected {
		want := strings.Fields(names)
		slices.Sort(want)
		slices.Sort(actual[boundary])
		if !slices.Equal(want, actual[boundary]) {
			t.Fatal("native inventory differs from the reviewed source", boundary)
		}
	}
	if len(actual) != len(expected) {
		t.Fatal("native inventory has an unreviewed boundary")
	}
}

func TestCapturePreservesNativeHostInputsAndFallbackPresence(t *testing.T) {
	t.Setenv("http_proxy", "PRIVATE_AMBIENT_PROXY")
	input := []string{
		"HTTP_PROXY=", "http_proxy=http://PRIVATE_PROXY:3128", "HOME=/PRIVATE_HOME",
		"PATH=/PRIVATE_PATH", "ProgramData=C:\\PRIVATE_DATA", "GCE_METADATA_HOST=PRIVATE_METADATA:8080",
		"IDENTITY_HEADER=PRIVATE_IDENTITY_HEADER", "MSI_SECRET=PRIVATE_MSI_SECRET", "EDITOR=PRIVATE_UNRELATED",
	}
	e, err := Capture(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range input[:len(input)-1] {
		name, want, _ := strings.Cut(entry, "=")
		if got, ok := e.lookup(name); !ok || got != want {
			t.Fatal("native host input or explicit fallback presence changed", name)
		}
	}
	if _, ok := e.lookup("EDITOR"); ok {
		t.Fatal("unrelated host input was captured")
	}
	input[1] = "http_proxy=PRIVATE_MUTATION"
	if got, _ := e.lookup("http_proxy"); got != "http://PRIVATE_PROXY:3128" {
		t.Fatal("caller mutated the captured native fallback")
	}
	for _, value := range []any{e, &e, struct{ Input Environment }{e}} {
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", value, value), "PRIVATE") {
			t.Fatal("native host input leaked through formatting", err)
		}
	}
}

func TestCaptureRejectsMalformedNativeFallbacksWithoutPartialInput(t *testing.T) {
	for _, entries := range [][]string{
		{"http_proxy=PRIVATE_FIRST", "http_proxy=PRIVATE_SECOND"},
		{"http_proxy"},
		{"http_proxy=PRIVATE\x00PROXY"},
		{"ProgramData=PRIVATE" + string([]byte{255})},
		{"IDENTITY_HEADER=PRIVATE\x00HEADER"},
		{"EVYDENCE_invalid=PRIVATE_VALUE"},
	} {
		e, err := Capture(entries)
		if !errors.Is(err, ErrInvalidEnvironment) || !reflect.DeepEqual(e, Environment{}) || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("malformed native input returned partial data or unsafe diagnostics", err)
		}
	}
}

func TestNativeSDKSourcePinsMatchModuleAndToolchain(t *testing.T) {
	data, err := os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	module, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{"go": module.Go.Version}
	for _, d := range module.Require {
		pins[d.Mod.Path] = d.Mod.Version
	}
	for _, d := range NativeDefinitions() {
		dependency, rest, ok := strings.Cut(d.Source, "@")
		version, _, hasPath := strings.Cut(rest, "/")
		if !ok || !hasPath || pins[dependency] != version {
			t.Fatal("native source inventory is stale against the pinned dependency", d.Name)
		}
	}
}

func TestNativeFallbackMetadataIsOwnedAndKeepsPrecedence(t *testing.T) {
	for _, d := range NativeDefinitions() {
		if d.Name == "HTTP_PROXY" && !slices.Equal(d.Fallbacks, []string{"http_proxy"}) {
			t.Fatal("Go transport uppercase-first proxy precedence changed")
		}
		if d.Name == "AWS_ACCESS_KEY_ID" && !slices.Equal(d.Fallbacks, []string{"AWS_ACCESS_KEY"}) {
			t.Fatal("AWS legacy credential fallback changed")
		}
		for i := range d.Fallbacks {
			d.Fallbacks[i] = "PRIVATE_MUTATION"
		}
		for i := range d.ExactChoices {
			d.ExactChoices[i] = "PRIVATE_MUTATION"
		}
	}
	for _, d := range NativeDefinitions() {
		if slices.Contains(d.Fallbacks, "PRIVATE_MUTATION") || slices.Contains(d.ExactChoices, "PRIVATE_MUTATION") {
			t.Fatal("native fallback metadata shares mutable storage")
		}
	}
}

func TestNativeSDKCredentialsAndProxyURLsAreClassifiedSecret(t *testing.T) {
	secretNames := strings.Fields(`AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_AUTHORIZATION_TOKEN AZURE_CLIENT_CERTIFICATE_PASSWORD AZURE_CLIENT_SECRET AZURE_PASSWORD AZURE_USERNAME IDENTITY_HEADER MSI_SECRET HTTP_PROXY HTTPS_PROXY`)
	for _, name := range secretNames {
		found := false
		for _, d := range NativeDefinitions() {
			if d.Name == name {
				found = true
				if !d.Secret || d.Default != "" {
					t.Fatal("native credential lacks secret classification or acquired a default", name)
				}
			}
		}
		if !found {
			t.Fatal("native credential is absent from the schema", name)
		}
	}
}
