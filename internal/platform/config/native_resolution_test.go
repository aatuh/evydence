package config

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolvePreservesNativeCredentialReferenceOwnership(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "PRIVATE_NONEXISTENT")
	for _, mode := range []string{"aws-kms", "gcp-kms", "azure-key-vault"} {
		e := roleEnvironment(t, API, true,
			"EVYDENCE_SIGNING_KEY_MODE="+mode,
			"EVYDENCE_GCP_KMS_KEY_NAME=projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
			"EVYDENCE_AZURE_KEY_VAULT_URL=https://vault.invalid", "EVYDENCE_AZURE_KEY_VAULT_KEY_NAME=key", "EVYDENCE_AZURE_KEY_VAULT_KEY_VERSION=1",
			"PGSERVICE=PRIVATE_SERVICE", "PGSERVICEFILE="+missing, "PGPASSFILE="+missing,
			"AWS_CONFIG_FILE="+missing, "AWS_SHARED_CREDENTIALS_FILE="+missing, "AWS_WEB_IDENTITY_TOKEN_FILE="+missing,
			"GOOGLE_APPLICATION_CREDENTIALS="+missing, "AZURE_FEDERATED_TOKEN_FILE="+missing, "AZURE_CLIENT_CERTIFICATE_PATH="+missing)
		input, err := Prepare(e, API)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := Resolve(context.Background(), input, true)
		if err != nil {
			t.Fatal("project-secret resolution entered a native credential loader", err)
		}
		native := cfg.Native()
		for _, path := range []NativeOption[string]{native.Postgres().ServiceFile, native.Postgres().PasswordFile, native.AWS().ConfigFile, native.AWS().SharedCredentialsFile, native.AWS().WebIdentityTokenFile, native.Google().CredentialsFile, native.Azure().FederatedTokenFile, native.Azure().ClientCertificatePath} {
			if !path.Present() || path.Value() != missing {
				t.Fatal("native reference was replaced or consumed by the project-secret reader")
			}
		}
		if !cfg.database.needsService {
			t.Fatal("unresolved native service was incorrectly declared complete")
		}
		encoded, err := json.Marshal(native)
		if err != nil || strings.Contains(string(encoded)+fmt.Sprintf("%v %#v", native, native), "PRIVATE") {
			t.Fatal("native credential references leaked through resolution")
		}
	}
}
