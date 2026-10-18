package config

func nativeHostDefinitions() []NativeDefinition {
	const proxy = "go@1.26.9/src/vendor/golang.org/x/net/http/httpproxy/proxy.go:FromEnvironment"
	var definitions []NativeDefinition
	for _, entry := range []struct{ name, fallback string }{
		{"HTTP_PROXY", "http_proxy"}, {"HTTPS_PROXY", "https_proxy"}, {"NO_PROXY", "no_proxy"},
	} {
		kind := URL
		if entry.name == "NO_PROXY" {
			kind = Text // Native grammar includes host suffixes, ports, IPs and wildcards.
		}
		d := nativeInput(NativeHost, proxy, entry.name, entry.name, kind, "Go HTTP transport setting; first nonempty uppercase value takes precedence over its lowercase fallback.")
		d.Roles, d.Fallbacks = runtimeRoles|CLI, []string{entry.fallback}
		d.Secret = kind == URL // Proxy URLs can carry credentials.
		if kind == URL {
			d.EndpointPolicy = NativeProxyEndpoint
		} else {
			d.Syntax, d.MaxItems, d.MaxItemBytes, d.RejectControl = NativeNoProxy, maxNativeListItems, 4096, true
		}
		definitions = append(definitions, d)
	}
	cgi := nativeInput(NativeHost, proxy, "REQUEST_METHOD", "cgi", Text, "A nonempty value enables the Go transport's CGI proxy restrictions.")
	cgi.Roles = runtimeRoles | CLI
	definitions = append(definitions, cgi)
	const executable = "go@1.26.9/src/os/exec/lp_windows.go:lookPathExts"
	extensions := nativeInput(NativeHost, executable, "PATHEXT", "windows_executable_extensions", Text, "Semicolon-separated Windows executable suffixes; normalize case and optional leading dots, skip empty items, and apply no native defaults during input parsing.")
	extensions.Syntax, extensions.MaxItems, extensions.MaxItemBytes, extensions.RejectControl = NativeWindowsExtensions, maxNativeListItems, 4096, true
	currentDirectory := nativeInput(NativeHost, executable, "NoDefaultCurrentDirectoryInExePath", "windows_skip_current_directory", Text, "Windows executable lookup skips the current directory when this input is present, including when its value is empty; consumers must check Present rather than HasValue.")
	definitions = append(definitions, extensions, currentDirectory)
	operatingSystem := nativeInput(NativeHost, "github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.21.1/runtime/policy_telemetry.go:platformInfo", "OS", "windows_sdk_operating_system", Text, "Windows operating-system label read by Azure SDK telemetry initialization; capture does not retroactively freeze SDK initialization. The Azure adapter disables SDK telemetry for default credentials it constructs; injected credentials and external tools retain their own policies.")
	operatingSystem.MaxBytes, operatingSystem.RejectControl = 256, true
	definitions = append(definitions, operatingSystem)
	for _, entry := range []struct{ name, parameter, source, description string }{
		{"HOME", "unix_home", "go@1.26.9/src/os/file.go:UserHomeDir", "Unix home input used by native AWS/Google credential-file defaults."},
		{"USERPROFILE", "windows_home", "go@1.26.9/src/os/file.go:UserHomeDir", "Windows home input used by native AWS credential-file defaults."},
		{"APPDATA", "windows_application_data", "golang.org/x/oauth2@v0.37.0/google/default.go:wellKnownFile", "Windows Google application-default credential directory."},
		{"ProgramData", "windows_program_data", "github.com/AzureAD/microsoft-authentication-library-for-go@v1.7.0/apps/managedidentity/managedidentity.go:getAzureArcPlatformPath", "Windows Azure Arc managed-identity filesystem base."},
		{"PATH", "executable_search_path", "go@1.26.9/src/os/exec/lp_unix.go:lookPath", "Native external credential helper search path; capture never executes a helper."},
		{"SYSTEMROOT", "windows_system_root", "github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.13.1/developer_credential_util_windows.go:buildCmd", "Windows system directory used by native developer credentials."},
		{"SSL_CERT_FILE", "system_certificate_file", "go@1.26.9/src/crypto/x509/root_unix.go:loadSystemRoots", "Unix system TLS trust-file override; resolution has a separate file owner."},
		{"SSL_CERT_DIR", "system_certificate_directories", "go@1.26.9/src/crypto/x509/root_unix.go:loadSystemRoots", "Platform-separated native TLS trust directories: colon on Unix, semicolon with native quote handling on Windows. Native resolution owns whether the running platform/toolchain uses this input."},
	} {
		kind := Path
		if entry.name == "PATH" || entry.name == "SSL_CERT_DIR" {
			kind = Text // Lists need their own bounded native grammar.
		}
		d := nativeInput(NativeHost, entry.source, entry.name, entry.parameter, kind, entry.description)
		if entry.name == "PATH" || entry.name == "SSL_CERT_DIR" {
			d.Syntax, d.MaxItems, d.MaxItemBytes, d.RejectControl = NativePathList, maxNativeListItems, 4096, true
			if entry.name == "SSL_CERT_DIR" {
				d.Syntax = NativeCertDirectories
			}
		}
		if entry.name == "SSL_CERT_FILE" || entry.name == "SSL_CERT_DIR" {
			d.Roles = databaseRoles | CLI
		}
		definitions = append(definitions, d)
	}
	return definitions
}
