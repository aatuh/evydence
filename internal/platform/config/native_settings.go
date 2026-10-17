package config

import "time"

// NativeSettings owns typed, role-scoped native inputs. Groups are value copies;
// NativeOption.Value copies lists and keeps implicit formatting redacted.
// Defaults and file/provider resolution belong to the later resolution phase.
type NativeSettings struct {
	redactedValue
	postgres NativePostgresSettings
	aws      NativeAWSSettings
	google   NativeGoogleSettings
	azure    NativeAzureSettings
	host     NativeHostSettings
}

func (s NativeSettings) Postgres() NativePostgresSettings { return s.postgres }
func (s NativeSettings) AWS() NativeAWSSettings           { return s.aws }
func (s NativeSettings) Google() NativeGoogleSettings     { return s.google }
func (s NativeSettings) Azure() NativeAzureSettings       { return s.azure }
func (s NativeSettings) Host() NativeHostSettings         { return s.host }

// NativePostgresSettings contains supplied native inputs without SDK defaults.
// Values are role-filtered before projection and redact ordinary formatting.
type NativePostgresSettings struct {
	redactedValue
	Hosts                   NativeOption[[]string]      `env:"PGHOST"`
	Ports                   NativeOption[[]uint16]      `env:"PGPORT"`
	Database                NativeOption[string]        `env:"PGDATABASE"`
	User                    NativeOption[string]        `env:"PGUSER"`
	Password                NativeOption[Secret]        `env:"PGPASSWORD"`
	PasswordFile            NativeOption[string]        `env:"PGPASSFILE"`
	ApplicationName         NativeOption[string]        `env:"PGAPPNAME"`
	ConnectTimeout          NativeOption[time.Duration] `env:"PGCONNECT_TIMEOUT"`
	SSLMode                 NativeOption[string]        `env:"PGSSLMODE"`
	SSLKeyFile              NativeOption[string]        `env:"PGSSLKEY"`
	SSLCertFile             NativeOption[string]        `env:"PGSSLCERT"`
	SSLSNI                  NativeOption[string]        `env:"PGSSLSNI"`
	SSLRootCertFile         NativeOption[string]        `env:"PGSSLROOTCERT"`
	SSLPassword             NativeOption[Secret]        `env:"PGSSLPASSWORD"`
	SSLNegotiation          NativeOption[string]        `env:"PGSSLNEGOTIATION"`
	TargetSessionAttributes NativeOption[string]        `env:"PGTARGETSESSIONATTRS"`
	Service                 NativeOption[string]        `env:"PGSERVICE"`
	ServiceFile             NativeOption[string]        `env:"PGSERVICEFILE"`
	Timezone                NativeOption[string]        `env:"PGTZ"`
	Options                 NativeOption[string]        `env:"PGOPTIONS"`
	MinProtocolVersion      NativeOption[string]        `env:"PGMINPROTOCOLVERSION"`
	MaxProtocolVersion      NativeOption[string]        `env:"PGMAXPROTOCOLVERSION"`
}

// NativeAWSSettings contains supplied native inputs without SDK defaults.
// Values are role-filtered before projection and redact ordinary formatting.
type NativeAWSSettings struct {
	redactedValue
	AccessKeyID                      NativeOption[Secret]    `env:"AWS_ACCESS_KEY_ID"`
	SecretAccessKey                  NativeOption[Secret]    `env:"AWS_SECRET_ACCESS_KEY"`
	SessionToken                     NativeOption[Secret]    `env:"AWS_SESSION_TOKEN"`
	AccountID                        NativeOption[string]    `env:"AWS_ACCOUNT_ID"`
	AccountIDEndpointMode            NativeOption[string]    `env:"AWS_ACCOUNT_ID_ENDPOINT_MODE"`
	AuthSchemePreference             NativeOption[[]string]  `env:"AWS_AUTH_SCHEME_PREFERENCE"`
	CABundleFile                     NativeOption[string]    `env:"AWS_CA_BUNDLE"`
	ConfigFile                       NativeOption[string]    `env:"AWS_CONFIG_FILE"`
	ContainerAuthorizationToken      NativeOption[Secret]    `env:"AWS_CONTAINER_AUTHORIZATION_TOKEN"`
	ContainerCredentialsFullURI      NativeOption[NativeURL] `env:"AWS_CONTAINER_CREDENTIALS_FULL_URI"`
	ContainerCredentialsRelativeURI  NativeOption[NativeURL] `env:"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"`
	DefaultsMode                     NativeOption[string]    `env:"AWS_DEFAULTS_MODE"`
	Profile                          NativeOption[string]    `env:"AWS_PROFILE"`
	Region                           NativeOption[string]    `env:"AWS_REGION"`
	DisableRequestCompression        NativeOption[bool]      `env:"AWS_DISABLE_REQUEST_COMPRESSION"`
	EC2MetadataDisabled              NativeOption[bool]      `env:"AWS_EC2_METADATA_DISABLED"`
	EC2MetadataServiceEndpoint       NativeOption[NativeURL] `env:"AWS_EC2_METADATA_SERVICE_ENDPOINT"`
	EC2MetadataServiceEndpointMode   NativeOption[string]    `env:"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE"`
	EC2MetadataV1Disabled            NativeOption[bool]      `env:"AWS_EC2_METADATA_V1_DISABLED"`
	EnableEndpointDiscovery          NativeOption[string]    `env:"AWS_ENABLE_ENDPOINT_DISCOVERY"`
	EndpointURL                      NativeOption[NativeURL] `env:"AWS_ENDPOINT_URL"`
	IgnoreConfiguredEndpointURLs     NativeOption[bool]      `env:"AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"`
	MaxAttempts                      NativeOption[int64]     `env:"AWS_MAX_ATTEMPTS"`
	RequestChecksumCalculation       NativeOption[string]    `env:"AWS_REQUEST_CHECKSUM_CALCULATION"`
	RequestMinCompressionSizeBytes   NativeOption[int64]     `env:"AWS_REQUEST_MIN_COMPRESSION_SIZE_BYTES"`
	ResponseChecksumValidation       NativeOption[string]    `env:"AWS_RESPONSE_CHECKSUM_VALIDATION"`
	RestrictFilePermissions          NativeOption[string]    `env:"AWS_RESTRICT_FILE_PERMISSIONS"`
	RetryMode                        NativeOption[string]    `env:"AWS_RETRY_MODE"`
	RoleARN                          NativeOption[string]    `env:"AWS_ROLE_ARN"`
	RoleSessionName                  NativeOption[string]    `env:"AWS_ROLE_SESSION_NAME"`
	S3DisableExpressSessionAuth      NativeOption[bool]      `env:"AWS_S3_DISABLE_EXPRESS_SESSION_AUTH"`
	S3DisableMultiregionAccessPoints NativeOption[bool]      `env:"AWS_S3_DISABLE_MULTIREGION_ACCESS_POINTS"`
	S3UseARNRegion                   NativeOption[bool]      `env:"AWS_S3_USE_ARN_REGION"`
	UserAgentAppID                   NativeOption[string]    `env:"AWS_SDK_UA_APP_ID"`
	SharedCredentialsFile            NativeOption[string]    `env:"AWS_SHARED_CREDENTIALS_FILE"`
	UseDualstackEndpoint             NativeOption[bool]      `env:"AWS_USE_DUALSTACK_ENDPOINT"`
	UseFIPSEndpoint                  NativeOption[bool]      `env:"AWS_USE_FIPS_ENDPOINT"`
	WebIdentityTokenFile             NativeOption[string]    `env:"AWS_WEB_IDENTITY_TOKEN_FILE"`
	ContainerAuthorizationTokenFile  NativeOption[string]    `env:"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"`
	LoginCacheDirectory              NativeOption[string]    `env:"AWS_LOGIN_CACHE_DIRECTORY"`
	ExecutionEnvironment             NativeOption[string]    `env:"AWS_EXECUTION_ENV"`
	KMSEndpoint                      NativeOption[NativeURL] `env:"AWS_ENDPOINT_URL_KMS"`
	STSEndpoint                      NativeOption[NativeURL] `env:"AWS_ENDPOINT_URL_STS"`
	SSOEndpoint                      NativeOption[NativeURL] `env:"AWS_ENDPOINT_URL_SSO"`
	SSOOIDCEndpoint                  NativeOption[NativeURL] `env:"AWS_ENDPOINT_URL_SSO_OIDC"`
	SigninEndpoint                   NativeOption[NativeURL] `env:"AWS_ENDPOINT_URL_SIGNIN"`
}

// NativeGoogleSettings contains supplied native inputs without SDK defaults.
// Values are role-filtered before projection and redact ordinary formatting.
type NativeGoogleSettings struct {
	redactedValue
	CredentialsFile  NativeOption[string]    `env:"GOOGLE_APPLICATION_CREDENTIALS"`
	AllowExecutables NativeOption[string]    `env:"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"`
	MetadataHost     NativeOption[NativeURL] `env:"GCE_METADATA_HOST"`
}

// NativeAzureSettings contains supplied native inputs without SDK defaults.
// Values are role-filtered before projection and redact ordinary formatting.
type NativeAzureSettings struct {
	redactedValue
	SDKLogging                 NativeOption[string]    `env:"AZURE_SDK_GO_LOGGING"`
	AdditionallyAllowedTenants NativeOption[[]string]  `env:"AZURE_ADDITIONALLY_ALLOWED_TENANTS"`
	AuthorityHost              NativeOption[NativeURL] `env:"AZURE_AUTHORITY_HOST"`
	ClientCertificatePassword  NativeOption[Secret]    `env:"AZURE_CLIENT_CERTIFICATE_PASSWORD"`
	ClientCertificatePath      NativeOption[string]    `env:"AZURE_CLIENT_CERTIFICATE_PATH"`
	ClientID                   NativeOption[string]    `env:"AZURE_CLIENT_ID"`
	ClientSecret               NativeOption[Secret]    `env:"AZURE_CLIENT_SECRET"`
	FederatedTokenFile         NativeOption[string]    `env:"AZURE_FEDERATED_TOKEN_FILE"`
	Password                   NativeOption[Secret]    `env:"AZURE_PASSWORD"`
	RegionalAuthorityName      NativeOption[string]    `env:"AZURE_REGIONAL_AUTHORITY_NAME"`
	TenantID                   NativeOption[string]    `env:"AZURE_TENANT_ID"`
	Username                   NativeOption[Secret]    `env:"AZURE_USERNAME"`
	SendCertificateChain       NativeOption[string]    `env:"AZURE_CLIENT_SEND_CERTIFICATE_CHAIN"`
	TokenCredentials           NativeOption[string]    `env:"AZURE_TOKEN_CREDENTIALS"`
	IdentityEndpoint           NativeOption[NativeURL] `env:"IDENTITY_ENDPOINT"`
	IdentityHeader             NativeOption[Secret]    `env:"IDENTITY_HEADER"`
	IdentityServerThumbprint   NativeOption[string]    `env:"IDENTITY_SERVER_THUMBPRINT"`
	MSIEndpoint                NativeOption[NativeURL] `env:"MSI_ENDPOINT"`
	MSISecret                  NativeOption[Secret]    `env:"MSI_SECRET"`
	IMDSEndpoint               NativeOption[NativeURL] `env:"IMDS_ENDPOINT"`
	DefaultIdentityClientID    NativeOption[string]    `env:"DEFAULT_IDENTITY_CLIENT_ID"`
}

// NativeHostSettings contains supplied native inputs without SDK defaults.
// Values are role-filtered before projection and redact ordinary formatting.
type NativeHostSettings struct {
	redactedValue
	HTTPProxy                          NativeOption[NativeURL] `env:"HTTP_PROXY"`
	HTTPSProxy                         NativeOption[NativeURL] `env:"HTTPS_PROXY"`
	NoProxy                            NativeOption[[]string]  `env:"NO_PROXY"`
	RequestMethod                      NativeOption[string]    `env:"REQUEST_METHOD"`
	Home                               NativeOption[string]    `env:"HOME"`
	UserProfile                        NativeOption[string]    `env:"USERPROFILE"`
	AppData                            NativeOption[string]    `env:"APPDATA"`
	ProgramData                        NativeOption[string]    `env:"ProgramData"`
	Path                               NativeOption[[]string]  `env:"PATH"`
	PathExtensions                     NativeOption[[]string]  `env:"PATHEXT"`
	NoDefaultCurrentDirectoryInExePath NativeOption[string]    `env:"NoDefaultCurrentDirectoryInExePath"`
	SystemRoot                         NativeOption[string]    `env:"SYSTEMROOT"`
	OperatingSystem                    NativeOption[string]    `env:"OS"`
	SystemCertificateFile              NativeOption[string]    `env:"SSL_CERT_FILE"`
	SystemCertificateDirectories       NativeOption[[]string]  `env:"SSL_CERT_DIR"`
}
