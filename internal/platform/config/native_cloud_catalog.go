package config

func nativeGoogleDefinitions() []NativeDefinition {
	credentials := nativeInput(NativeGoogle, "golang.org/x/oauth2@v0.37.0/google/default.go:FindDefaultCredentialsWithParams", "GOOGLE_APPLICATION_CREDENTIALS", "credentials_file", Path, "Explicit Google application-default credential file reference.")
	executables := nativeInput(NativeGoogle, "golang.org/x/oauth2@v0.37.0/google/externalaccount/executablecredsource.go:getTokenFromExecutableCommand", "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "allow_executables", Choice, "Native external-account executable opt-in: only 1 enables execution; capture never executes it.")
	executables.Allowed = []string{"0", "1"}
	metadata := nativeInput(NativeGoogle, "cloud.google.com/go/compute/metadata@v0.9.0/metadata.go:OnGCE", "GCE_METADATA_HOST", "metadata_host", Text, "Google metadata host:port override; also affects native metadata discovery.")
	metadata.Syntax = NativeMetadataHost
	return []NativeDefinition{credentials, executables, metadata}
}

func nativeAzureDefinitions() []NativeDefinition {
	const identity = "github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/azidentity.go"
	var definitions []NativeDefinition
	for _, entry := range []struct {
		name, parameter, description string
		kind                         Kind
	}{
		{"AZURE_ADDITIONALLY_ALLOWED_TENANTS", "additionally_allowed_tenants", "Semicolon-separated additional tenants accepted by the native credential.", Text},
		{"AZURE_AUTHORITY_HOST", "authority_host", "Native Azure identity authority URL.", URL},
		{"AZURE_CLIENT_CERTIFICATE_PASSWORD", "client_certificate_password", "Native client certificate password.", Text},
		{"AZURE_CLIENT_CERTIFICATE_PATH", "client_certificate_path", "Native client certificate/private-key file reference.", Path},
		{"AZURE_CLIENT_ID", "client_id", "Native client or managed-identity client identifier.", Text},
		{"AZURE_CLIENT_SECRET", "client_secret", "Native confidential-client credential.", Text},
		{"AZURE_FEDERATED_TOKEN_FILE", "federated_token_file", "Native workload-identity token file reference.", Path},
		{"AZURE_PASSWORD", "password", "Native username/password credential password.", Text},
		{"AZURE_REGIONAL_AUTHORITY_NAME", "regional_authority_name", "Native regional identity authority selection.", Text},
		{"AZURE_TENANT_ID", "tenant_id", "Native Azure credential tenant identifier.", Text},
		{"AZURE_USERNAME", "username", "Native username/password credential identity.", Text},
	} {
		d := nativeInput(NativeAzure, identity, entry.name, entry.parameter, entry.kind, entry.description)
		switch entry.name {
		case "AZURE_ADDITIONALLY_ALLOWED_TENANTS":
			d.Syntax, d.MaxItems, d.MaxItemBytes, d.RejectControl = NativeTenants, maxNativeListItems, 4096, true
		case "AZURE_CLIENT_CERTIFICATE_PASSWORD", "AZURE_CLIENT_SECRET", "AZURE_PASSWORD", "AZURE_USERNAME":
			d.Secret = true
		}
		definitions = append(definitions, d)
	}
	chain := nativeInput(NativeAzure, "github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/environment_credential.go:NewEnvironmentCredential", "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN", "client_send_certificate_chain", Choice, "Native certificate-chain switch: 1/true enables it; legacy other values disable it.")
	chain.Allowed = []string{"0", "1", "true", "false"}
	credential := nativeInput(NativeAzure, "github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/default_azure_credential.go:NewDefaultAzureCredential", "AZURE_TOKEN_CREDENTIALS", "token_credentials", Choice, "Native credential selection: dev/prod are case-sensitive; credential type names are case-insensitive; present empty input is invalid.")
	credential.Allowed = []string{"dev", "prod", "EnvironmentCredential", "WorkloadIdentityCredential", "ManagedIdentityCredential", "AzureCLICredential", "AzureDeveloperCLICredential", "AzurePowerShellCredential"}
	credential.ExactChoices = []string{"dev", "prod"}
	credential.RejectEmpty = true
	definitions = append(definitions, chain, credential)
	logging := nativeInput(NativeAzure, "github.com/Azure/azure-sdk-for-go/sdk/internal@v1.12.0/log/log.go:initLogging", "AZURE_SDK_GO_LOGGING", "sdk_logging", Choice, "Native Azure SDK raw stderr logging switch. The Azure adapter clears the global listener during process initialization in all profiles; production rejects an explicit all request. Application diagnostics use structured events.")
	logging.Allowed, logging.ProductionAllowed, logging.CaseSensitive = []string{"off", "all"}, []string{"", "off"}, true
	definitions = append(definitions, logging)
	const managed = "github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/managedidentity.go:GetSource"
	for _, entry := range []struct {
		name, parameter, description string
		kind                         Kind
	}{
		{"IDENTITY_ENDPOINT", "identity_endpoint", "Native Azure managed-identity endpoint selected by MSAL.", URL},
		{"IDENTITY_HEADER", "identity_header", "Native managed-identity authorization header value.", Text},
		{"IDENTITY_SERVER_THUMBPRINT", "identity_server_thumbprint", "Native managed-identity server certificate thumbprint.", Text},
		{"MSI_ENDPOINT", "msi_endpoint", "Native legacy managed-identity endpoint.", URL},
		{"MSI_SECRET", "msi_secret", "Native legacy managed-identity authorization secret.", Text},
		{"IMDS_ENDPOINT", "imds_endpoint", "Native Azure Arc metadata endpoint selection.", URL},
		{"DEFAULT_IDENTITY_CLIENT_ID", "default_identity_client_id", "Native Azure ML managed-identity client identifier.", Text},
	} {
		source := managed
		if entry.name == "DEFAULT_IDENTITY_CLIENT_ID" {
			source = "github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/azure_ml.go:createAzureMLAuthRequest"
		}
		d := nativeInput(NativeAzure, source, entry.name, entry.parameter, entry.kind, entry.description)
		if entry.kind == URL {
			d.EndpointPolicy = NativeIdentityEndpoint
		}
		d.Secret = entry.name == "IDENTITY_HEADER" || entry.name == "MSI_SECRET"
		d.RejectControl = d.Secret || entry.kind == URL
		definitions = append(definitions, d)
	}
	return definitions
}
