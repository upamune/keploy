// Package load runs recorded test cases as a local load test.
package load

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"go.keploy.io/server/v3/config"
	"go.keploy.io/server/v3/pkg"
	"go.keploy.io/server/v3/pkg/models"
	"go.uber.org/zap"
)

// TestDB is the test-case store consumed by the load service.
type TestDB interface {
	GetAllTestSetIDs(ctx context.Context) ([]string, error)
	GetTestCases(ctx context.Context, testSetID string) ([]*models.TestCase, error)
}

// Service runs local load tests from recorded test cases.
type Service interface {
	Run(ctx context.Context) (*Summary, error)
}

// Load is the concrete load-test service.
type Load struct {
	logger *zap.Logger
	testDB TestDB
	cfg    *config.Config
}

// Summary contains aggregate load-test results.
type Summary struct {
	Requests uint64
	Failures uint64
	Duration time.Duration
	Min      time.Duration
	Max      time.Duration
	P50      time.Duration
	P95      time.Duration
}

// New creates a load-test service.
func New(logger *zap.Logger, testDB TestDB, cfg *config.Config) *Load {
	return &Load{logger: logger, testDB: testDB, cfg: cfg}
}

// Run executes the configured load test against an already-running app.
func (l *Load) Run(ctx context.Context) (*Summary, error) {
	testSets, err := l.selectedTestSets(ctx)
	if err != nil {
		return nil, err
	}
	tests, err := l.loadHTTPTests(ctx, testSets)
	if err != nil {
		return nil, err
	}
	if len(tests) == 0 {
		return nil, fmt.Errorf("no HTTP test cases found for load test")
	}

	vus := l.cfg.Load.VUs
	if vus == 0 {
		vus = 1
	}
	duration := l.cfg.Load.Duration
	if duration <= 0 {
		duration = 30 * time.Second
	}

	runCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	latencies := make(chan time.Duration, 1024)
	var requests atomic.Uint64
	var failures atomic.Uint64
	var wg sync.WaitGroup

	for vu := uint32(0); vu < vus; vu++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			i := offset
			for {
				select {
				case <-runCtx.Done():
					return
				default:
				}
				tc := tests[i%len(tests)]
				i++
				start := time.Now()
				_, err := pkg.SimulateHTTP(runCtx, tc, tc.Type, l.logger, l.simulationConfig())
				elapsed := time.Since(start)
				requests.Add(1)
				if err != nil {
					failures.Add(1)
				}
				select {
				case latencies <- elapsed:
				default:
				}
			}
		}(int(vu))
	}

	wg.Wait()
	close(latencies)

	summary := summarize(latencies, requests.Load(), failures.Load(), duration)
	l.logger.Info("load test completed",
		zap.Uint64("requests", summary.Requests),
		zap.Uint64("failures", summary.Failures),
		zap.Duration("duration", summary.Duration),
		zap.Duration("p50", summary.P50),
		zap.Duration("p95", summary.P95),
	)
	return summary, nil
}

func (l *Load) selectedTestSets(ctx context.Context) ([]string, error) {
	if len(l.cfg.Load.TestSets) > 0 {
		return l.cfg.Load.TestSets, nil
	}
	return l.testDB.GetAllTestSetIDs(ctx)
}

func (l *Load) loadHTTPTests(ctx context.Context, testSets []string) ([]*models.TestCase, error) {
	var out []*models.TestCase
	for _, testSet := range testSets {
		tcs, err := l.testDB.GetTestCases(ctx, testSet)
		if err != nil {
			return nil, fmt.Errorf("load test cases for %s: %w", testSet, err)
		}
		for _, tc := range tcs {
			if tc != nil && (tc.Kind == models.HTTP || tc.Kind == models.HTTP2) {
				cp := *tc
				cp.Type = testSet
				out = append(out, &cp)
			}
		}
	}
	return out, nil
}

func (l *Load) simulationConfig() pkg.SimulationConfig {
	host := l.cfg.Test.Host
	if host == "" {
		host = "localhost"
	}
	port := l.cfg.Test.Port
	if port == 0 {
		port = l.cfg.Port
	}
	return pkg.SimulationConfig{
		APITimeout: l.cfg.Test.APITimeout,
		ConfigPort: port,
		KeployPath: l.cfg.Path,
		ConfigHost: host,
	}
}

func summarize(latencies <-chan time.Duration, requests, failures uint64, duration time.Duration) *Summary {
	values := make([]time.Duration, 0)
	for latency := range latencies {
		values = append(values, latency)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	s := &Summary{Requests: requests, Failures: failures, Duration: duration}
	if len(values) == 0 {
		return s
	}
	s.Min = values[0]
	s.Max = values[len(values)-1]
	s.P50 = percentile(values, 0.50)
	s.P95 = percentile(values, 0.95)
	return s
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}
