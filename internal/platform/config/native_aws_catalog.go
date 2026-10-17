package config

import "math"

func nativeAWSDefinitions() []NativeDefinition {
	const source = "github.com/aws/aws-sdk-go-v2/config@v1.32.20/env_config.go:NewEnvConfig"
	var definitions []NativeDefinition
	for _, entry := range []struct {
		name, parameter, description string
		kind                         Kind
	}{
		{"AWS_ACCESS_KEY_ID", "access_key_id", "Native AWS access-key identity; supports the legacy AWS_ACCESS_KEY fallback.", Text},
		{"AWS_SECRET_ACCESS_KEY", "secret_access_key", "Native AWS secret access key; supports the legacy AWS_SECRET_KEY fallback.", Text},
		{"AWS_SESSION_TOKEN", "session_token", "Native AWS temporary-session credential.", Text},
		{"AWS_ACCOUNT_ID", "account_id", "Account identity attached to native environment credentials.", Text},
		{"AWS_ACCOUNT_ID_ENDPOINT_MODE", "account_id_endpoint_mode", "Native account endpoint selection: preferred, required or disabled (case-sensitive).", Choice},
		{"AWS_AUTH_SCHEME_PREFERENCE", "auth_scheme_preference", "Ordered comma-separated native authentication scheme preference.", Text},
		{"AWS_CA_BUNDLE", "ca_bundle", "Native custom TLS trust-bundle file reference.", Path},
		{"AWS_CONFIG_FILE", "config_file", "Native shared AWS configuration file reference.", Path},
		{"AWS_CONTAINER_AUTHORIZATION_TOKEN", "container_authorization_token", "Credential-endpoint authorization header value.", Text},
		{"AWS_CONTAINER_CREDENTIALS_FULL_URI", "container_credentials_full_uri", "Explicit native container credential endpoint.", URL},
		{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "container_credentials_relative_uri", "Relative native container credential path.", Text},
		{"AWS_DEFAULTS_MODE", "defaults_mode", "Native SDK default-setting profile.", Choice},
		{"AWS_PROFILE", "profile", "Native shared configuration profile; AWS_DEFAULT_PROFILE is its fallback.", Text},
		{"AWS_REGION", "region", "Native region; AWS_DEFAULT_REGION is its fallback, beneath the explicit signing region.", Text},
		{"AWS_DISABLE_REQUEST_COMPRESSION", "disable_request_compression", "Native request-compression switch.", Boolean},
		{"AWS_EC2_METADATA_DISABLED", "ec2_metadata_disabled", "Native EC2 metadata credential-discovery switch.", Boolean},
		{"AWS_EC2_METADATA_SERVICE_ENDPOINT", "ec2_metadata_service_endpoint", "Native EC2 metadata endpoint override.", URL},
		{"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE", "ec2_metadata_service_endpoint_mode", "Native EC2 metadata address family: IPv4 or IPv6.", Choice},
		{"AWS_EC2_METADATA_V1_DISABLED", "ec2_metadata_v1_disabled", "Native IMDSv1 fallback switch.", Boolean},
		{"AWS_ENABLE_ENDPOINT_DISCOVERY", "enable_endpoint_discovery", "Native endpoint discovery: true, false or auto.", Choice},
		{"AWS_ENDPOINT_URL", "endpoint_url", "Native global service endpoint override.", URL},
		{"AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "ignore_configured_endpoint_urls", "Ignore native endpoint overrides from environment and shared configuration.", Boolean},
		{"AWS_MAX_ATTEMPTS", "max_attempts", "Native retry count; zero retains the SDK's default selection.", Integer},
		{"AWS_REQUEST_CHECKSUM_CALCULATION", "request_checksum_calculation", "Native request checksum policy.", Choice},
		{"AWS_REQUEST_MIN_COMPRESSION_SIZE_BYTES", "request_min_compression_size_bytes", "Native compression threshold, bounded to 10 MiB by the pinned SDK.", Integer},
		{"AWS_RESPONSE_CHECKSUM_VALIDATION", "response_checksum_validation", "Native response checksum validation policy.", Choice},
		{"AWS_RESTRICT_FILE_PERMISSIONS", "restrict_file_permissions", "Native credential-cache file permission policy.", Choice},
		{"AWS_RETRY_MODE", "retry_mode", "Native standard or adaptive retry policy.", Choice},
		{"AWS_ROLE_ARN", "role_arn", "Native assumed-role identity.", Text},
		{"AWS_ROLE_SESSION_NAME", "role_session_name", "Native assumed-role session label.", Text},
		{"AWS_S3_DISABLE_EXPRESS_SESSION_AUTH", "s3_disable_express_session_auth", "S3 Express authentication setting read by the shared AWS config loader.", Boolean},
		{"AWS_S3_DISABLE_MULTIREGION_ACCESS_POINTS", "s3_disable_multiregion_access_points", "S3 setting read even when constructing the native KMS configuration.", Boolean},
		{"AWS_S3_USE_ARN_REGION", "s3_use_arn_region", "S3 ARN-region setting read by the shared AWS config loader.", Boolean},
		{"AWS_SDK_UA_APP_ID", "sdk_ua_app_id", "Native SDK user-agent application label.", Text},
		{"AWS_SHARED_CREDENTIALS_FILE", "shared_credentials_file", "Native shared credential file reference.", Path},
		{"AWS_USE_DUALSTACK_ENDPOINT", "use_dualstack_endpoint", "Native dual-stack service endpoint switch.", Boolean},
		{"AWS_USE_FIPS_ENDPOINT", "use_fips_endpoint", "Native FIPS service endpoint switch.", Boolean},
		{"AWS_WEB_IDENTITY_TOKEN_FILE", "web_identity_token_file", "Native web-identity token file reference.", Path},
	} {
		d := nativeInput(NativeAWS, source, entry.name, entry.parameter, entry.kind, entry.description)
		switch entry.name {
		case "AWS_ACCESS_KEY_ID":
			d.Secret, d.Fallbacks = true, []string{"AWS_ACCESS_KEY"}
		case "AWS_SECRET_ACCESS_KEY":
			d.Secret, d.Fallbacks = true, []string{"AWS_SECRET_KEY"}
		case "AWS_SESSION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN":
			d.Secret = true
			d.RejectControl = true
		case "AWS_REGION":
			d.Fallbacks = []string{"AWS_DEFAULT_REGION"}
		case "AWS_PROFILE":
			d.Fallbacks = []string{"AWS_DEFAULT_PROFILE"}
		case "AWS_ACCOUNT_ID_ENDPOINT_MODE":
			d.Allowed = []string{"preferred", "required", "disabled"}
			d.CaseSensitive = true
		case "AWS_DEFAULTS_MODE":
			d.Allowed = []string{"legacy", "standard", "in-region", "cross-region", "mobile", "auto"}
		case "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE":
			d.Allowed = []string{"IPv4", "IPv6"}
		case "AWS_ENABLE_ENDPOINT_DISCOVERY":
			d.Allowed = []string{"true", "false", "auto"}
		case "AWS_MAX_ATTEMPTS":
			d.Max = math.MaxInt32
		case "AWS_REQUEST_MIN_COMPRESSION_SIZE_BYTES":
			d.Max = 10485760
		case "AWS_REQUEST_CHECKSUM_CALCULATION", "AWS_RESPONSE_CHECKSUM_VALIDATION":
			d.Allowed = []string{"when_supported", "when_required"}
		case "AWS_RESTRICT_FILE_PERMISSIONS":
			d.Allowed = []string{"user_read_write", "unrestricted"}
		case "AWS_RETRY_MODE":
			d.Allowed = []string{"standard", "adaptive"}
		}
		definitions = append(definitions, d)
	}
	for _, entry := range []struct{ name, parameter, source string }{
		{"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "container_authorization_token_file", "github.com/aws/aws-sdk-go-v2/config@v1.32.20/resolve_credentials.go:resolveHTTPCredProvider"},
		{"AWS_LOGIN_CACHE_DIRECTORY", "login_cache_directory", "github.com/aws/aws-sdk-go-v2/config@v1.32.20/resolve_credentials.go:resolveLoginCredentials"},
		{"AWS_EXECUTION_ENV", "execution_env", "github.com/aws/aws-sdk-go-v2/config@v1.32.20/defaultsmode.go:resolveDefaultsModeRuntimeEnvironment"},
	} {
		kind := Path
		if entry.name == "AWS_EXECUTION_ENV" {
			kind = Text
		}
		definitions = append(definitions, nativeInput(NativeAWS, entry.source, entry.name, entry.parameter, kind, "Native AWS credential/default resolver input; resolution follows validation."))
	}
	for _, service := range []struct{ suffix, module, version string }{
		{"KMS", "kms", "v1.52.2"}, {"STS", "sts", "v1.42.3"}, {"SSO", "sso", "v1.30.19"},
		{"SSO_OIDC", "ssooidc", "v1.36.2"}, {"SIGNIN", "signin", "v1.1.1"},
	} {
		definitions = append(definitions, nativeInput(NativeAWS,
			"github.com/aws/aws-sdk-go-v2/service/"+service.module+"@"+service.version+"/api_client.go:ServiceID",
			"AWS_ENDPOINT_URL_"+service.suffix, "endpoint_url_"+service.module, URL,
			"Service-specific endpoint name computed by the native config loader from ServiceID; includes credential-chain services."))
	}
	return definitions
}
