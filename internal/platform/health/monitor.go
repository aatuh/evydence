// Package health samples bounded process dependencies without retaining their
// errors. Refresh work belongs to one caller; concurrent callers share its
// result. There is no background goroutine or detached dependency work.
package health

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"time"
)

const (
	DefaultCacheTTL       = 2 * time.Second
	DefaultCheckTimeout   = time.Second
	DefaultRefreshTimeout = 3 * time.Second
	maxDuration           = 10 * time.Second
	maxChecks             = 16
)

type Status string

const (
	OK          Status = "ok"
	Unavailable Status = "unavailable"
)

// Check contains only a code-owned dependency name and a cooperative bounded
// probe. Startup marks dependencies required for initialization (such as schema
// state), independently of dependencies required only for serving work.
type Check struct {
	Name    string
	Startup bool
	Timeout time.Duration
	Check   func(context.Context) error
}

type Config struct {
	CacheTTL, CheckTimeout, RefreshTimeout time.Duration
	// Now is optional and must be safe for concurrent calls. It supports a
	// deterministic clock in tests; production uses time.Now's monotonic clock.
	Now func() time.Time
}

type Result struct {
	Name    string
	Status  Status
	Startup bool
}

// Snapshot contains no raw dependency errors or mutable shared cache storage.
// A sample can take RefreshTimeout; reuse lasts at most CacheTTL after that
// sample finishes. Both durations are bounded, including cached failures.
type Snapshot struct {
	Initialized, Draining      bool
	StartupReady, Ready        bool
	SampleStartedAt, CheckedAt time.Time
	ValidUntil                 time.Time
	Checks                     []Result
}

type Monitor struct {
	mu          sync.Mutex
	checks      []Check
	config      Config
	initialized bool
	draining    bool
	hasSnapshot bool
	cached      Snapshot
	refreshing  chan struct{}
}

var checkName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func New(checks []Check, config Config) (*Monitor, error) {
	if config.CacheTTL == 0 {
		config.CacheTTL = DefaultCacheTTL
	}
	if config.CheckTimeout == 0 {
		config.CheckTimeout = DefaultCheckTimeout
	}
	if config.RefreshTimeout == 0 {
		config.RefreshTimeout = DefaultRefreshTimeout
	}
	for _, duration := range []time.Duration{config.CacheTTL, config.CheckTimeout, config.RefreshTimeout} {
		if duration <= 0 || duration > maxDuration {
			return nil, errors.New("health timing must be positive and at most ten seconds")
		}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if len(checks) > maxChecks {
		return nil, errors.New("too many process health dependencies")
	}
	owned := append([]Check(nil), checks...)
	seen := make(map[string]bool, len(owned))
	for index := range owned {
		check := &owned[index]
		if !checkName.MatchString(check.Name) || check.Check == nil || seen[check.Name] {
			return nil, errors.New("health dependencies require unique safe names and probe functions")
		}
		if check.Timeout == 0 {
			check.Timeout = config.CheckTimeout
		}
		if check.Timeout <= 0 || check.Timeout > maxDuration {
			return nil, errors.New("health dependency timeout must be positive and at most ten seconds")
		}
		seen[check.Name] = true
	}
	return &Monitor{checks: owned, config: config}, nil
}

// Live does no dependency work. A process that cannot schedule its HTTP
// liveness handler cannot answer the caller's bounded liveness probe.
func (m *Monitor) Live() bool { return m != nil }

func (m *Monitor) MarkInitialized() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.initialized = true
	m.mu.Unlock()
}

func (m *Monitor) MarkDraining() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.draining = true
	m.mu.Unlock()
}

func (m *Monitor) Snapshot(ctx context.Context) (Snapshot, error) {
	if m == nil || ctx == nil {
		return Snapshot{}, errors.New("health monitor and context are required")
	}
	for {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		m.mu.Lock()
		if !m.initialized || m.draining {
			result := m.decorate(Snapshot{})
			m.mu.Unlock()
			return result, nil
		}
		now := m.config.Now()
		if m.hasSnapshot && !now.Before(m.cached.CheckedAt) && now.Before(m.cached.ValidUntil) {
			result := m.decorate(m.cached)
			m.mu.Unlock()
			return result, nil
		}
		if m.refreshing != nil {
			finished := m.refreshing
			m.mu.Unlock()
			select {
			case <-ctx.Done():
				return Snapshot{}, ctx.Err()
			case <-finished:
				continue
			}
		}
		finished := make(chan struct{})
		m.refreshing = finished
		m.mu.Unlock()

		result, err := m.refresh(ctx)
		m.mu.Lock()
		if err == nil {
			m.cached, m.hasSnapshot = result, true
			result = m.decorate(result)
		}
		m.refreshing = nil
		close(finished)
		m.mu.Unlock()
		return result, err
	}
}

// decorate runs under mu. Initialization and drain flags are always current,
// even if they changed while a dependency refresh was in progress.
func (m *Monitor) decorate(sample Snapshot) Snapshot {
	sample.Checks = append([]Result{}, sample.Checks...)
	sample.Initialized, sample.Draining = m.initialized, m.draining
	sample.StartupReady = m.initialized && !m.draining
	sample.Ready = sample.StartupReady
	for _, check := range sample.Checks {
		if check.Status != OK {
			sample.Ready = false
			if check.Startup {
				sample.StartupReady = false
			}
		}
	}
	return sample
}

func (m *Monitor) refresh(ctx context.Context) (Snapshot, error) {
	result := Snapshot{SampleStartedAt: m.config.Now(), Checks: make([]Result, 0, len(m.checks))}
	refreshCtx, cancelRefresh := context.WithTimeout(ctx, m.config.RefreshTimeout)
	defer cancelRefresh()
	for _, check := range m.checks {
		status := Unavailable
		if refreshCtx.Err() == nil {
			checkCtx, cancel := context.WithTimeout(refreshCtx, check.Timeout)
			if safelyProbe(checkCtx, check.Check) {
				status = OK
			}
			cancel()
		}
		result.Checks = append(result.Checks, Result{Name: check.Name, Status: status, Startup: check.Startup})
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	result.CheckedAt = m.config.Now()
	result.ValidUntil = result.CheckedAt.Add(m.config.CacheTTL)
	return result, nil
}

func safelyProbe(ctx context.Context, check func(context.Context) error) (healthy bool) {
	defer func() {
		if recover() != nil {
			healthy = false
		}
	}()
	return check(ctx) == nil && ctx.Err() == nil
}
