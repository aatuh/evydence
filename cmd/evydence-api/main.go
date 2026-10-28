package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/identity/httpvalidator"
	"github.com/aatuh/evydence/internal/adapters/identity/oidcdiscovery"
	"github.com/aatuh/evydence/internal/adapters/identity/oidcuserinfo"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/adapters/signing/awskms"
	"github.com/aatuh/evydence/internal/adapters/signing/azurekeyvault"
	"github.com/aatuh/evydence/internal/adapters/signing/gcpkms"
	signinggateway "github.com/aatuh/evydence/internal/adapters/signing/httpgateway"
	"github.com/aatuh/evydence/internal/adapters/transparency/httpfetcher"
	transparencygateway "github.com/aatuh/evydence/internal/adapters/transparency/httpgateway"
	cosignverification "github.com/aatuh/evydence/internal/adapters/verification/sigstore"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/confighealth"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/platform/wiring"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

const runtimeReadinessTimeout = 5 * time.Second

// This process owns clients returned by its constructor. Tests can supply a
// signing port while exercising production startup without real provider calls.
var newAPISigningExecutor = openSigningExecutorConfigured

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runWithContext(ctx); err != nil {
		os.Exit(1)
	}
}

func runWithContext(ctx context.Context) error {
	return run(ctx)
}

func run(ctx context.Context) error {
	environment, err := config.Capture(os.Environ())
	if err != nil {
		logging.RejectStartup(ctx, "api", runtimeinfo.Current(), os.Stderr)
		return err
	}
	return runAPIProcess(ctx, environment, os.Stderr, runAPIConfigured)
}

func runAPIConfigured(ctx context.Context, settings config.Configuration, database postgres.PreparedPoolConfig) (runErr error) {
	runtimeSettings, apiSettings, providerSettings := settings.Runtime(), settings.API(), settings.Providers()
	cleanupTimeout := runtimeSettings.ShutdownCleanupTimeout
	configurationProbe, err := confighealth.NewConfigured(ctx, settings, confighealth.ProcessSource)
	if err != nil {
		return err
	}
	identity := runtimeinfo.Current()
	production := settings.Production()
	pepper := apiSettings.KeyPepper.Reveal()
	profile := wiring.Profile(runtimeSettings.Profile)
	httpConfig := httpRuntimeConfigFromSettings(apiSettings)
	var providers wiring.OwnedResources
	var runtime *wiring.Runtime
	defer func() { runErr = closeAPIResources(ctx, runErr, runtime, &providers, cleanupTimeout) }()
	oidcClient := oidcdiscovery.New(oidcdiscovery.Config{
		AllowInsecureForLocalhost: providerSettings.OIDCDiscoveryAllowInsecureLocalhost,
		Timeout:                   providerSettings.OIDCDiscoveryTimeout,
	})
	ownNewProvider(&providers, "oidc_discovery", oidcClient)
	providerValidator, err := openProviderIdentityValidatorConfigured(providerSettings)
	if err != nil {
		return err
	}
	ownNewProvider(&providers, "identity_provider", providerValidator)
	transparencyFetcher, err := openTransparencyProofFetcherConfigured(providerSettings)
	if err != nil {
		return err
	}
	ownNewProvider(&providers, "transparency_provider", transparencyFetcher)
	cosignVerifier, err := openCosignVerifierConfigured(providerSettings)
	if err != nil {
		return err
	}
	ownNewProvider(&providers, "verification_provider", cosignVerifier)
	signer, err := newAPISigningExecutor(ctx, providerSettings)
	if err != nil {
		return err
	}
	ownNewProvider(&providers, "signing_provider", signer)
	startupCtx, cancelStartup := context.WithTimeout(ctx, 30*time.Second)
	defer cancelStartup()
	migrationsDir := runtimeSettings.MigrationsDir
	runtimeConfiguration := apiRuntimeConfigFromSettings(settings, database)
	runtimeConfiguration.Cosign, runtimeConfiguration.OIDC, runtimeConfiguration.ProviderAPI = cosignVerifier, oidcClient, providerValidator
	runtimeConfiguration.SigningExecutor, runtimeConfiguration.TransparencyProofs = signer, transparencyFetcher
	runtimeConfiguration.CloseOwnedProviders = providers.CloseWithin
	runtime, err = wiring.OpenRuntime(startupCtx, runtimeConfiguration)
	if err != nil {
		return err
	}
	var readinessChecks []app.ReadinessCheck
	pgStore := runtime.Postgres
	objectStore := runtime.Objects
	readinessChecks = append(readinessChecks,
		app.ReadinessCheck{Name: "configuration", Timeout: runtimeReadinessTimeout, FailureDetail: "loaded configuration is unavailable or stale", Check: configurationProbe},
		app.ReadinessCheck{Name: "postgres", Timeout: runtimeReadinessTimeout, FailureDetail: "database connectivity is unavailable", Check: pgStore.CheckReadiness},
		app.ReadinessCheck{Name: "migrations", Timeout: runtimeReadinessTimeout, FailureDetail: "database migration state is unavailable", Check: func(checkCtx context.Context) error {
			return pgStore.CheckMigrationState(checkCtx, migrationsDir)
		}},
		app.ReadinessCheck{Name: "outbox", Timeout: runtimeReadinessTimeout, FailureDetail: "outbox progress is unavailable", Check: pgStore.CheckOutboxReadiness},
	)
	if production {
		readinessChecks = append(readinessChecks, app.ReadinessCheck{Name: "writer_lease", Timeout: runtimeReadinessTimeout, FailureDetail: "API writer lease is unavailable", Check: pgStore.CheckAPIWriterLease})
	}
	objectReadiness, ok := objectStore.(interface{ CheckReadiness(context.Context) error })
	if !ok {
		return errors.New("configured object store does not provide readiness checks")
	}
	readinessChecks = append(readinessChecks, app.ReadinessCheck{Name: "object_store", Timeout: runtimeReadinessTimeout, FailureDetail: "object store access is unavailable", Check: objectReadiness.CheckReadiness})
	logging.Emit(ctx, logging.Command, logging.Fields{OperationID: "runtime_open", Result: logging.Succeeded})
	if production {
		readinessChecks = append(readinessChecks, app.ReadinessCheck{Name: "signing_config", Timeout: runtimeReadinessTimeout, FailureDetail: "required signing dependency is unavailable", Check: signingConfigurationReadiness(signer)})
	}
	bootstrapDisabled := apiSettings.BootstrapDisabled
	printBootstrapSecret := apiSettings.PrintBootstrapSecret
	bootstrapInput := tenantBootstrapInputFromSettings(apiSettings)
	if profile == wiring.PostgreSQL && !bootstrapDisabled {
		commands, err := wiring.BuildTenantBootstrapCommands(runtime.Postgres, pepper, production)
		if err != nil {
			return fmt.Errorf("compose tenant bootstrap: %w", err)
		}
		bootstrapContext, cancelBootstrap := context.WithTimeout(ctx, 30*time.Second)
		bootstrap, err := commands.BootstrapFirstTenant(bootstrapContext, bootstrapInput)
		cancelBootstrap()
		if err != nil {
			return fmt.Errorf("bootstrap tenant: %w", err)
		}
		if bootstrap.Created {
			logging.Emit(ctx, logging.Bootstrap, logging.Fields{TenantID: bootstrap.Tenant.ID, ResourceID: bootstrap.Key.ID, Result: logging.Succeeded})
		}
		// Publish any explicitly requested local secret immediately after the
		// durable commit; later server startup failures cannot hide it.
		if err := writeTenantBootstrapResult(os.Stdout, bootstrap, production, printBootstrapSecret); err != nil {
			return err
		}
	}
	options, err := wiring.BuildAPIReadServices(runtime, pepper, readinessChecks)
	if err != nil {
		return fmt.Errorf("compose API read services: %w", err)
	}
	observability, err := wiring.BuildOperationalTelemetry(ctx, wiring.API, runtimeSettings, options.OperationalMetrics)
	if err != nil {
		return fmt.Errorf("compose operational telemetry: %w", err)
	}
	defer observability.Close(ctx)
	options.OperationalMetrics = observability
	options.RateLimitRequestsPerMinute = httpConfig.RateLimitRequestsPerMinute
	options.AuthenticationFailuresPerMinute = httpConfig.AuthenticationFailuresPerMinute
	options.ExpensiveTenantRequestsPerMinute = httpConfig.ExpensiveTenantRequestsPerMinute
	options.RateLimitBucketCapacity = httpConfig.RateLimitBucketCapacity
	options.TrustedProxyCIDRs = httpConfig.TrustedProxyCIDRs
	options.MaxURLBytes = httpConfig.MaxURLBytes
	options.MaxInboundRequestBytes = httpConfig.MaxInboundRequestBytes
	options.MaxInFlightRequests = httpConfig.MaxInFlightRequests
	options.MaxConcurrentUploads = httpConfig.MaxConcurrentUploads
	options.Logger = logging.FromContext(ctx)
	options.BuildIdentity = identity
	options.PaginationSecret = []byte(pepper)
	server, err := httpapi.NewNativeServerWithOptionsContext(ctx, options)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}
	readinessLifecycle, ok := options.ReadinessQuery.(interface{ MarkDraining() })
	if !ok {
		return errors.New("API readiness lifecycle control is required")
	}
	addr := apiSettings.Address
	httpServer := newHTTPServer(addr, server.Handler(), httpConfig)
	httpServer.ErrorLog = log.New(logging.DiagnosticWriter(ctx), "", 0)
	logging.Emit(ctx, logging.Command, logging.Fields{OperationID: "api_listen", Result: logging.Succeeded})
	return serveHTTP(ctx, httpServer, httpConfig.ShutdownTimeout, readinessLifecycle.MarkDraining)
}

func tenantBootstrapInputFromSettings(settings config.APISettings) identityapp.BootstrapTenantInput {
	// Shared preflight validates raw byte/text bounds without trimming the name.
	return identityapp.BootstrapTenantInput{TenantName: settings.BootstrapTenant, APIKeyName: "local-admin", Scopes: []string{"*"}}
}

func writeTenantBootstrapResult(output io.Writer, result wiring.TenantBootstrapResult, production, printSecret bool) error {
	if production && printSecret {
		return errors.New("production refuses EVYDENCE_PRINT_BOOTSTRAP_SECRET=true")
	}
	if !result.Created {
		return nil
	}
	if printSecret {
		key := domain.APIKey(result.Key)
		key.Hash = ""
		if err := json.NewEncoder(output).Encode(map[string]any{"tenant_id": result.Tenant.ID, "api_key": key, "secret": result.Secret}); err != nil {
			return errors.New("bootstrap credentials could not be written")
		}
		return nil
	}
	return nil
}

func openSigningExecutorConfigured(ctx context.Context, settings config.ProviderSettings) (app.SigningExecutor, error) {
	mode := strings.ReplaceAll(settings.SigningKeyMode, "-", "_")
	if mode == "aws_kms" {
		executor, err := awskms.New(ctx, awskms.Config{
			Region: settings.AWSRegion, KeyID: settings.AWSKMSKeyID, Endpoint: settings.AWSKMSEndpoint,
			SigningAlgorithm: settings.AWSKMSSigningAlgorithm, Timeout: settings.AWSKMSTimeout,
		})
		if err != nil {
			return nil, fmt.Errorf("configure AWS KMS signing executor: %w", err)
		}
		return executor, nil
	}
	if mode == "gcp_kms" {
		executor, err := gcpkms.New(ctx, gcpkms.Config{Endpoint: settings.GCPKMSEndpoint, KeyName: settings.GCPKMSKeyName, Timeout: settings.GCPKMSTimeout})
		if err != nil {
			return nil, fmt.Errorf("configure GCP KMS signing executor: %w", err)
		}
		return executor, nil
	}
	if mode == "azure_key_vault" {
		executor, err := azurekeyvault.New(azurekeyvault.Config{
			VaultURL: settings.AzureKeyVaultURL, KeyName: settings.AzureKeyVaultKeyName, KeyVersion: settings.AzureKeyVaultKeyVersion,
			Algorithm: settings.AzureKeyVaultAlgorithm, APIVersion: settings.AzureKeyVaultAPIVersion, Timeout: settings.AzureKeyVaultTimeout,
		})
		if err != nil {
			return nil, fmt.Errorf("configure Azure Key Vault signing executor: %w", err)
		}
		return executor, nil
	}
	if settings.SigningExecutorURL == "" {
		return nil, nil
	}
	executor, err := signinggateway.New(signinggateway.Config{
		Endpoint: settings.SigningExecutorURL, ReadinessEndpoint: settings.SigningExecutorReadinessURL,
		BearerToken: settings.SigningExecutorToken.Reveal(), VerificationPublicKey: base64.StdEncoding.EncodeToString(settings.SigningExecutorPublicKey()),
		AllowInsecureForLocalhost: settings.SigningExecutorAllowInsecureLocalhost, Timeout: settings.SigningExecutorTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("configure signing executor: %w", err)
	}
	return executor, nil
}

func openTransparencyProofFetcherConfigured(settings config.ProviderSettings) (app.TransparencyProofFetcher, error) {
	if settings.TransparencyProofGatewayURL != "" {
		fetcher, err := transparencygateway.New(transparencygateway.Config{
			Endpoint: settings.TransparencyProofGatewayURL, BearerToken: settings.TransparencyProofGatewayToken.Reveal(),
			AllowInsecureForLocalhost: settings.TransparencyProofGatewayAllowInsecureLocalhost, Timeout: settings.TransparencyProofGatewayTimeout,
		})
		if err != nil {
			return nil, fmt.Errorf("configure transparency proof gateway: %w", err)
		}
		return fetcher, nil
	}
	return httpfetcher.New(httpfetcher.Config{AllowInsecureForLocalhost: settings.TransparencyFetchAllowInsecureLocalhost, Timeout: settings.TransparencyFetchTimeout}), nil
}

// Public trust material has already passed the shared bounded decoder/parser.
// The verifier retains its own trust validation and offline-bundle contract.
func openCosignVerifierConfigured(settings config.ProviderSettings) (app.CosignPolicyVerifier, error) {
	rootJSON, publicKey := settings.SigstoreTrustRootJSON(), settings.SigstoreTrustedPublicKeyPEM()
	if len(rootJSON) == 0 && len(publicKey) == 0 {
		return nil, nil
	}
	verifier, err := cosignverification.New(cosignverification.Config{
		TrustedRootJSON: rootJSON, TrustRootVersion: settings.SigstoreTrustRootVersion, TrustedPublicKeyPEM: publicKey,
	})
	if err != nil {
		return nil, errors.New("configured Sigstore trust material is invalid")
	}
	return verifier, nil
}

func openProviderIdentityValidatorConfigured(settings config.ProviderSettings) (app.ProviderIdentityValidator, error) {
	if settings.ProviderValidationGatewayURL != "" {
		validator, err := httpvalidator.New(httpvalidator.Config{
			Endpoint: settings.ProviderValidationGatewayURL, BearerToken: settings.ProviderValidationGatewayToken.Reveal(),
			AllowInsecureForLocalhost: settings.ProviderValidationGatewayAllowInsecureLocalhost, Timeout: settings.ProviderValidationGatewayTimeout,
		})
		if err != nil {
			return nil, fmt.Errorf("configure provider validation gateway: %w", err)
		}
		return validator, nil
	}
	return oidcuserinfo.New(oidcuserinfo.Config{AllowInsecureForLocalhost: settings.OIDCUserInfoAllowInsecureLocalhost, Timeout: settings.OIDCUserInfoTimeout}), nil
}

func signingConfigurationReadiness(signer app.SigningExecutor) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if signer == nil {
			return errors.New("signing executor is not configured")
		}
		probe, ok := signer.(interface{ CheckReadiness(context.Context) error })
		if !ok {
			return errors.New("signing executor does not provide operational readiness")
		}
		return probe.CheckReadiness(ctx)
	}
}

func newHTTPServer(addr string, handler http.Handler, config httpRuntimeConfig) *http.Server {
	return &http.Server{
		ErrorLog:          log.New(io.Discard, "", 0),
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: config.ReadHeaderTimeout,
		ReadTimeout:       config.ReadTimeout,
		WriteTimeout:      config.WriteTimeout,
		IdleTimeout:       config.IdleTimeout,
		MaxHeaderBytes:    config.MaxHeaderBytes,
	}
}

var errAPIForcedDrain = errors.New("API forced drain requires process exit; in-flight outcomes may be uncertain")

func serveHTTP(ctx context.Context, server *http.Server, shutdownTimeout time.Duration, markDraining func()) error {
	if ctx == nil || server == nil {
		return errors.New("API server and context are required")
	}
	if ctx.Err() != nil {
		return apiStopError(ctx)
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", server.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return apiStopError(ctx)
		}
		return err
	}
	return serveHTTPOnListener(ctx, server, listener, shutdownTimeout, markDraining)
}

func serveHTTPOnListener(ctx context.Context, server *http.Server, listener net.Listener, shutdownTimeout time.Duration, markDraining func()) error {
	// This function takes ownership of the supplied listener, including on a
	// startup failure. Once Serve starts, net/http owns its once-only close.
	if ctx == nil || server == nil || listener == nil {
		if listener != nil {
			_ = listener.Close()
		}
		return errors.New("API server, listener and context are required")
	}
	if ctx.Err() != nil {
		closeErr := listener.Close()
		return errors.Join(apiStopError(ctx), closeErr)
	}
	if shutdownTimeout <= 0 {
		shutdownTimeout = 30 * time.Second
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	var serveErr error
	serveFinished := false
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		serveErr, serveFinished = err, true
	case <-ctx.Done():
	}
	// Serve can fail while accepted connections are still processing. Drain
	// those requests before the caller closes their storage/provider resources.
	if markDraining != nil {
		markDraining()
	}
	logging.Emit(ctx, logging.Drain, logging.Fields{Result: logging.Started})
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logging.Emit(ctx, logging.Drain, logging.Fields{Result: logging.Uncertain})
		closeErr := server.Close()
		return errors.Join(errAPIForcedDrain, serveErr, fmt.Errorf("gracefully shut down API server: %w", err), closeErr)
	}
	if !serveFinished {
		serveErr = <-errCh
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
	}
	logging.Emit(ctx, logging.Drain, logging.Fields{Result: logging.Succeeded})
	return errors.Join(serveErr, apiStopError(ctx))
}

func apiStopError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	return ctx.Err()
}
