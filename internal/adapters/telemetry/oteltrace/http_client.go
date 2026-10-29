package oteltrace

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// Config consumes already validated daemon settings. HTTPClient permits an
// explicit trust pool in owned local fixtures; its cookies, redirects, proxy,
// timeouts and credentials are not inherited. Production wiring supplies nil.
type Config struct {
	Enabled          bool
	Service          string
	Endpoint         string
	SamplePerMillion int64
	QueueSize        int
	ExportTimeout    time.Duration
	ShutdownTimeout  time.Duration
	HTTPClient       *http.Client
}

func (Config) String() string               { return "oteltrace.Config{redacted}" }
func (Config) GoString() string             { return "oteltrace.Config{redacted}" }
func (Config) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

func (c Config) validate() error {
	if (c.Service != "api" && c.Service != "worker") || c.SamplePerMillion < 0 || c.SamplePerMillion > 1000000 || c.QueueSize < 16 || c.QueueSize > 1024 || c.ExportTimeout < time.Second || c.ExportTimeout > 5*time.Second || c.ShutdownTimeout < time.Second || c.ShutdownTimeout > time.Minute {
		return ErrConfiguration
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || len(c.Endpoint) > 4096 || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(c.Endpoint, "#") || strings.Contains(u.Hostname(), "%") {
		return ErrConfiguration
	}
	if port := u.Port(); port != "" {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || value == 0 {
			return ErrConfiguration
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return ErrConfiguration
	}
	return nil
}

type httpClient struct {
	endpoint  string
	service   string
	client    *http.Client
	transport *http.Transport
	mu        sync.Mutex
	active    map[*http.Request]context.CancelFunc
	stopped   bool
	done      chan struct{}
}

var _ otlptrace.Client = (*httpClient)(nil)

func newHTTPClient(cfg Config) (*httpClient, error) {
	trust := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.HTTPClient != nil && cfg.HTTPClient.Transport != nil {
		transport, ok := cfg.HTTPClient.Transport.(*http.Transport)
		if !ok || (transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify) {
			return nil, ErrConfiguration
		}
		if transport.TLSClientConfig != nil && transport.TLSClientConfig.RootCAs != nil {
			trust.RootCAs = transport.TLSClientConfig.RootCAs.Clone()
		}
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: cfg.ExportTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     trust,
		TLSHandshakeTimeout: cfg.ExportTimeout, ResponseHeaderTimeout: cfg.ExportTimeout,
		MaxIdleConns: 1, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1,
		IdleConnTimeout: 30 * time.Second, DisableCompression: true,
	}
	client := &http.Client{Transport: transport, Timeout: cfg.ExportTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errExport },
	}
	return &httpClient{endpoint: cfg.Endpoint, service: "evydence-" + cfg.Service, client: client, transport: transport, active: make(map[*http.Request]context.CancelFunc), done: make(chan struct{})}, nil
}

// MarshalLog prevents recursive SDK configuration logging from exposing the
// collector address or transport internals, even with a replacement SDK logger.
func (*httpClient) MarshalLog() any { return "evydence.otlp.http" }
func (*httpClient) String() string  { return "evydence.otlp.http" }

func (*httpClient) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		return errExport
	}
	return nil
}

func (c *httpClient) UploadTraces(ctx context.Context, spans []*tracepb.ResourceSpans) error {
	if ctx.Err() != nil {
		return errExport
	}
	// SDK WithResource merges OTEL_RESOURCE_ATTRIBUTES even with an explicit
	// resource. Replace the entire envelope before serialization; never forward
	// its attributes, schema URL or dropped-attribute metadata. No host/process
	// resource detectors are registered by this adapter.
	owned := make([]*tracepb.ResourceSpans, 0, len(spans))
	for _, batch := range spans {
		if batch == nil {
			continue
		}
		owned = append(owned, &tracepb.ResourceSpans{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: c.service}},
			}}},
			ScopeSpans: batch.ScopeSpans,
		})
	}
	body, err := proto.Marshal(&collectortrace.ExportTraceServiceRequest{ResourceSpans: owned})
	if err != nil || len(body) > 1024*1024 {
		return errExport
	}
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return errExport
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return errExport
	}
	c.active[request] = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.active, request)
		if c.stopped && len(c.active) == 0 {
			close(c.done)
		}
		c.mu.Unlock()
	}()
	request.Header.Set("Content-Type", "application/x-protobuf")
	response, err := c.client.Do(request)
	if err != nil {
		return errExport
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 || response.StatusCode != http.StatusOK {
		return errExport
	}
	var result collectortrace.ExportTraceServiceResponse
	if err := proto.Unmarshal(data, &result); err != nil || result.GetPartialSuccess().GetRejectedSpans() != 0 {
		return errExport
	}
	return nil
}

func (c *httpClient) Stop(ctx context.Context) error {
	c.mu.Lock()
	if !c.stopped {
		c.stopped = true
		for _, cancel := range c.active {
			cancel()
		}
		if len(c.active) == 0 {
			close(c.done)
		}
	}
	c.mu.Unlock()
	c.transport.CloseIdleConnections()
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return errExport
	}
}
