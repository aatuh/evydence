package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const (
	defaultRateLimitBucketCapacity = 10_000
	defaultMaxURLBytes             = 8 << 10
	defaultMaxInFlightRequests     = 256
	defaultMaxConcurrentUploads    = 8
)

// ingressControl keeps attacker-controlled network state bounded before a
// request reaches application handlers. The process configures limits through
// ServerOptions; zero-valued rate limits deliberately disable only that rate
// dimension, not the request-concurrency or URL-size safety limits.
type ingressControl struct {
	edgeLimiter             *requestRateLimiter
	tenantExpensiveLimiter  *requestRateLimiter
	trustedProxyCIDRs       []netip.Prefix
	maxURLBytes             int
	maxInboundRequestBytes  int64
	inFlightRequests        chan struct{}
	concurrentNativeUploads chan struct{}
}

func newIngressControl(opts ServerOptions) (*ingressControl, error) {
	trusted, err := parseTrustedProxyCIDRs(opts.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	bucketCapacity := opts.RateLimitBucketCapacity
	if bucketCapacity <= 0 {
		bucketCapacity = defaultRateLimitBucketCapacity
	}
	maxURLBytes := opts.MaxURLBytes
	if maxURLBytes <= 0 {
		maxURLBytes = defaultMaxURLBytes
	}
	maxInboundRequestBytes := opts.MaxInboundRequestBytes
	if maxInboundRequestBytes <= 0 {
		maxInboundRequestBytes = app.EvidenceDocumentLimit
	}
	maxInFlightRequests := opts.MaxInFlightRequests
	if maxInFlightRequests <= 0 {
		maxInFlightRequests = defaultMaxInFlightRequests
	}
	maxConcurrentUploads := opts.MaxConcurrentUploads
	if maxConcurrentUploads <= 0 {
		maxConcurrentUploads = defaultMaxConcurrentUploads
	}
	return &ingressControl{
		edgeLimiter:             newRequestRateLimiter(opts.RateLimitRequestsPerMinute, bucketCapacity),
		tenantExpensiveLimiter:  newRequestRateLimiter(opts.ExpensiveTenantRequestsPerMinute, bucketCapacity),
		trustedProxyCIDRs:       trusted,
		maxURLBytes:             maxURLBytes,
		maxInboundRequestBytes:  maxInboundRequestBytes,
		inFlightRequests:        make(chan struct{}, maxInFlightRequests),
		concurrentNativeUploads: make(chan struct{}, maxConcurrentUploads),
	}, nil
}

func parseTrustedProxyCIDRs(values []string) ([]netip.Prefix, error) {
	trusted := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, app.NewValidationError()
		}
		trusted = append(trusted, prefix.Masked())
	}
	return trusted, nil
}

func (s *Server) ingressValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ingress == nil {
			next.ServeHTTP(w, r)
			return
		}
		requestURI := r.RequestURI
		if requestURI == "" && r.URL != nil {
			requestURI = r.URL.RequestURI()
		}
		if len(requestURI) > s.ingress.maxURLBytes || r.ContentLength > s.ingress.maxInboundRequestBytes {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		if !allowsIdentityContentEncoding(r) || isMultipartRequest(r) {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.ingress.maxInboundRequestBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// Evydence does not accept compressed request bodies. This makes the bytes
// counted by the shared HTTP and handler limits the bytes parsed and staged,
// rather than trusting a proxy-specific decompression policy.
func allowsIdentityContentEncoding(r *http.Request) bool {
	values := r.Header.Values("Content-Encoding")
	if len(values) == 0 {
		return true
	}
	return len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), "identity")
}

// Multipart request bodies are not part of the Evydence API contract. Reject
// them at ingress instead of letting multipart part counts or temporary-file
// behavior become an unbounded secondary parser.
func isMultipartRequest(r *http.Request) bool {
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	return strings.HasPrefix(contentType, "multipart/")
}

func (s *Server) inFlightMiddleware(next http.Handler) http.Handler {
	return s.boundedConcurrencyMiddleware(next, func() chan struct{} {
		if s.ingress == nil {
			return nil
		}
		return s.ingress.inFlightRequests
	})
}

func (s *Server) uploadConcurrencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ingress == nil || !isNativeUploadRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !tryAcquire(s.ingress.concurrentNativeUploads) {
			writeProblem(w, r, app.ErrRateLimited)
			return
		}
		defer release(s.ingress.concurrentNativeUploads)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) boundedConcurrencyMiddleware(next http.Handler, semaphore func() chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket := semaphore()
		if bucket == nil {
			next.ServeHTTP(w, r)
			return
		}
		if !tryAcquire(bucket) {
			writeProblem(w, r, app.ErrRateLimited)
			return
		}
		defer release(bucket)
		next.ServeHTTP(w, r)
	})
}

func tryAcquire(semaphore chan struct{}) bool {
	select {
	case semaphore <- struct{}{}:
		return true
	default:
		return false
	}
}

func release(semaphore chan struct{}) {
	<-semaphore
}

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	if s.ingress == nil || s.ingress.edgeLimiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ingress.edgeLimiter.allow(s.clientRateLimitKey(r), time.Now().UTC()) {
			writeProblem(w, r, app.ErrRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowExpensiveTenantRequest(actor domain.Actor, r *http.Request) bool {
	if s.ingress == nil || s.ingress.tenantExpensiveLimiter == nil {
		return true
	}
	route, ok := expensiveTenantRoute(r)
	if !ok {
		return true
	}
	return s.ingress.tenantExpensiveLimiter.allow(actor.TenantID+"\x00"+route, time.Now().UTC())
}

// expensiveTenantRoute is intentionally a small explicit allowlist. It keeps
// potentially CPU, storage, or export-heavy endpoints from sharing a tenant
// quota with routine API reads and records a separate bucket per route.
func expensiveTenantRoute(r *http.Request) (string, bool) {
	if r == nil || r.URL == nil || r.Method != http.MethodPost {
		return "", false
	}
	path := r.URL.Path
	if isNativeUploadRequest(r) {
		return r.Method + " " + path, true
	}
	switch path {
	case "/v1/evidence-bundles", "/v1/evidence-bundles/import", "/v1/sbom-diffs", "/v1/openapi-diffs", "/v1/evidence-summaries", "/v1/evidence-graph-snapshots", "/v1/customer-packages", "/v1/questionnaire-packages", "/v1/reports/pdf", "/v1/reports/anomaly", "/v1/policies/evaluate":
		return r.Method + " " + path, true
	}
	if strings.HasPrefix(path, "/v1/report-templates/") && strings.HasSuffix(path, "/render") {
		return r.Method + " " + path, true
	}
	if strings.HasPrefix(path, "/v1/custom-policies/") && strings.HasSuffix(path, "/evaluate") {
		return r.Method + " " + path, true
	}
	return "", false
}

func isNativeUploadRequest(r *http.Request) bool {
	if r == nil || r.URL == nil || r.Method != http.MethodPost {
		return false
	}
	switch r.URL.Path {
	case "/v1/sboms", "/v1/sboms/spdx", "/v1/vex", "/v1/vex/cyclonedx", "/v1/vulnerability-scans", "/v1/openapi-contracts":
		return true
	default:
		return false
	}
}

func (s *Server) clientRateLimitKey(r *http.Request) string {
	remote, ok := remoteAddress(r)
	if !ok {
		return "unknown"
	}
	if s.ingress == nil || !isTrustedProxy(remote, s.ingress.trustedProxyCIDRs) {
		return remote.String()
	}
	if forwarded, ok := forwardedClientAddress(r.Header.Values("X-Forwarded-For"), s.ingress.trustedProxyCIDRs); ok {
		return forwarded.String()
	}
	return remote.String()
}

func remoteAddress(r *http.Request) (netip.Addr, bool) {
	if r == nil {
		return netip.Addr{}, false
	}
	remote := strings.TrimSpace(r.RemoteAddr)
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		remote = host
	}
	address, err := netip.ParseAddr(remote)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func forwardedClientAddress(values []string, trusted []netip.Prefix) (netip.Addr, bool) {
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return netip.Addr{}, false
	}
	parts := strings.Split(values[0], ",")
	for index := len(parts) - 1; index >= 0; index-- {
		address, err := netip.ParseAddr(strings.TrimSpace(parts[index]))
		if err != nil {
			return netip.Addr{}, false
		}
		address = address.Unmap()
		if !isTrustedProxy(address, trusted) {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func isTrustedProxy(address netip.Addr, trusted []netip.Prefix) bool {
	for _, prefix := range trusted {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

type requestRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	capacity int
	buckets  map[string]rateLimitBucket
}

type rateLimitBucket struct {
	reset    time.Time
	lastSeen time.Time
	used     int
}

func newRequestRateLimiter(limit, capacity int) *requestRateLimiter {
	if limit <= 0 {
		return nil
	}
	if capacity <= 0 {
		capacity = defaultRateLimitBucketCapacity
	}
	return &requestRateLimiter{limit: limit, window: time.Minute, capacity: capacity, buckets: map[string]rateLimitBucket{}}
}

func (l *requestRateLimiter) allow(key string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket, found := l.buckets[key]
	if !found {
		l.makeSpace(now)
		bucket = rateLimitBucket{reset: now.Add(l.window)}
	} else if !now.Before(bucket.reset) {
		bucket = rateLimitBucket{reset: now.Add(l.window)}
	}
	bucket.lastSeen = now
	if bucket.used >= l.limit {
		l.buckets[key] = bucket
		return false
	}
	bucket.used++
	l.buckets[key] = bucket
	return true
}

func (l *requestRateLimiter) makeSpace(now time.Time) {
	for key, bucket := range l.buckets {
		if !now.Before(bucket.reset) {
			delete(l.buckets, key)
		}
	}
	for len(l.buckets) >= l.capacity {
		var oldestKey string
		var oldest time.Time
		for key, bucket := range l.buckets {
			if oldestKey == "" || bucket.lastSeen.Before(oldest) {
				oldestKey, oldest = key, bucket.lastSeen
			}
		}
		delete(l.buckets, oldestKey)
	}
}

func (l *requestRateLimiter) bucketCount() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
