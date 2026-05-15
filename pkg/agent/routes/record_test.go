package routes

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreAgent "go.keploy.io/server/v3/pkg/agent"
	pTls "go.keploy.io/server/v3/pkg/agent/proxy/tls"
	"go.keploy.io/server/v3/pkg/models"
	serviceAgent "go.keploy.io/server/v3/pkg/service/agent"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// redirectAgentReadyFile rewrites the package-level agentReadyFilePath
// to a sandboxed path under t.TempDir() so tests exercise the real
// os.WriteFile path without clobbering /tmp/agent.ready on the host.
// The original value is restored via t.Cleanup.
func redirectAgentReadyFile(t *testing.T) string {
	t.Helper()
	orig := agentReadyFilePath
	sandbox := filepath.Join(t.TempDir(), "agent.ready")
	agentReadyFilePath = sandbox
	t.Cleanup(func() { agentReadyFilePath = orig })
	return sandbox
}

// newTestAgent builds a routes.Agent with a test logger and nil service —
// MakeAgentReady does not touch svc, so a nil service is safe.
func newTestAgent(t *testing.T) *Agent {
	t.Helper()
	return &Agent{
		logger: zaptest.NewLogger(t, zaptest.Level(zap.WarnLevel)),
	}
}

func TestMakeAgentReady_RefusesWhenCANotReady(t *testing.T) {
	// Reset the package-level CAReady signal so this test observes the
	// "not ready" state regardless of previous tests in the binary.
	pTls.ResetCAReadyForTest()

	readyFile := redirectAgentReadyFile(t)
	a := newTestAgent(t)

	req := httptest.NewRequest(http.MethodPost, "/agent/agent/ready", nil)
	rr := httptest.NewRecorder()

	a.MakeAgentReady(rr, req)

	if got, want := rr.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("status: got %d, want %d", got, want)
	}
	// Confirm the readiness file was NOT touched on the 503 path —
	// that's the whole point of the gate.
	if _, err := os.Stat(readyFile); !os.IsNotExist(err) {
		t.Fatalf("agent.ready must not be created on 503; stat err=%v", err)
	}
}

func TestMakeAgentReady_SucceedsWhenCAReady(t *testing.T) {
	pTls.ResetCAReadyForTest()
	pTls.CloseCAReadyForTest()

	readyFile := redirectAgentReadyFile(t)
	a := newTestAgent(t)

	req := httptest.NewRequest(http.MethodPost, "/agent/agent/ready", nil)
	rr := httptest.NewRecorder()

	a.MakeAgentReady(rr, req)

	if got, want := rr.Code, http.StatusOK; got != want {
		t.Fatalf("status: got %d, want %d; body=%q", got, want, rr.Body.String())
	}
	if _, err := os.Stat(readyFile); err != nil {
		t.Fatalf("agent.ready must be written on 200: %v", err)
	}
}

// TestMakeAgentReady_SurfacesCASetupFailure verifies that a terminal
// SetupCA error recorded via MarkCAFailed is reflected in the 503
// body instead of the generic "not yet written" message, and that
// the readiness file is NOT created. This is the failure-mode
// Copilot raised: without this path, operators see endless 503s with
// no diagnostic when SetupCA errored out at boot.
func TestMakeAgentReady_SurfacesCASetupFailure(t *testing.T) {
	pTls.ResetCAReadyForTest()
	pTls.MarkCAFailed(errors.New("synthetic: no writable CA store"))

	readyFile := redirectAgentReadyFile(t)
	a := newTestAgent(t)

	rr := httptest.NewRecorder()
	a.MakeAgentReady(rr, httptest.NewRequest(http.MethodPost, "/agent/agent/ready", nil))

	if got, want := rr.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("status: got %d, want %d; body=%q", got, want, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "CA setup failed") {
		t.Fatalf("body should surface setup error, got %q", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "synthetic: no writable CA store") {
		t.Fatalf("body should echo the underlying error, got %q", rr.Body.String())
	}
	if _, err := os.Stat(readyFile); !os.IsNotExist(err) {
		t.Fatalf("agent.ready must not be created on CA-setup-failure 503; stat err=%v", err)
	}

	// Clear the failure so subsequent tests in the binary see a
	// clean baseline regardless of ordering.
	pTls.ResetCAReadyForTest()
}

// TestMakeAgentReady_NoReadinessFileOn503 is a tight regression guard
// for the exact failure mode the gate protects against: an app
// container observing /tmp/agent.ready and booting before the CA
// bundle is on disk. It is intentionally narrower than the 503 test
// above so a regression lights up here first.
func TestMakeAgentReady_NoReadinessFileOn503(t *testing.T) {
	pTls.ResetCAReadyForTest()

	readyFile := redirectAgentReadyFile(t)
	a := newTestAgent(t)

	// Hit the endpoint several times; every call must 503 and none
	// must ever create the readiness file.
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		a.MakeAgentReady(rr, httptest.NewRequest(http.MethodPost, "/agent/agent/ready", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("call %d: expected 503, got %d", i, rr.Code)
		}
		if _, err := os.Stat(readyFile); !os.IsNotExist(err) {
			t.Fatalf("call %d: agent.ready leaked (stat err=%v)", i, err)
		}
	}

	// Now flip the signal and verify the next call writes the file.
	pTls.CloseCAReadyForTest()
	rr := httptest.NewRecorder()
	a.MakeAgentReady(rr, httptest.NewRequest(http.MethodPost, "/agent/agent/ready", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("after CA ready: expected 200, got %d", rr.Code)
	}
	if _, err := os.Stat(readyFile); err != nil {
		t.Fatalf("after CA ready: expected agent.ready on disk: %v", err)
	}
}

type freezeRouteSvc struct {
	set   time.Time
	clear int
}

func (f *freezeRouteSvc) Setup(context.Context, chan int) error { return nil }
func (f *freezeRouteSvc) StartIncomingProxy(context.Context, models.IncomingOptions) (chan *models.TestCase, error) {
	return nil, nil
}
func (f *freezeRouteSvc) GetOutgoing(context.Context, models.OutgoingOptions) (<-chan *models.Mock, error) {
	return nil, nil
}
func (f *freezeRouteSvc) GetMapping(context.Context) (<-chan models.TestMockMapping, error) {
	return nil, nil
}
func (f *freezeRouteSvc) MockOutgoing(context.Context, models.OutgoingOptions) error { return nil }
func (f *freezeRouteSvc) SetMocks(context.Context, []*models.Mock, []*models.Mock) error {
	return nil
}
func (f *freezeRouteSvc) GetConsumedMocks(context.Context) ([]models.MockState, error) {
	return nil, nil
}
func (f *freezeRouteSvc) GetMockErrors(context.Context) ([]models.UnmatchedCall, error) {
	return nil, nil
}
func (f *freezeRouteSvc) StoreMocks(context.Context, []*models.Mock, []*models.Mock) error {
	return nil
}
func (f *freezeRouteSvc) UpdateMockParams(context.Context, models.MockFilterParams) error {
	return nil
}
func (f *freezeRouteSvc) SetGracefulShutdown(context.Context) error { return nil }
func (f *freezeRouteSvc) SubscribePcap(io.Writer, func()) (func(), error) {
	return nil, nil
}
func (f *freezeRouteSvc) StreamPcap(context.Context, io.Writer, func()) error { return nil }
func (f *freezeRouteSvc) StreamKeylog(context.Context, io.Writer) error       { return nil }
func (f *freezeRouteSvc) SetFreezeAnchor(context.Context, time.Time) error    { return nil }
func (f *freezeRouteSvc) SetFreezeTime(_ context.Context, ts time.Time) error {
	f.set = ts
	return nil
}
func (f *freezeRouteSvc) ClearFreezeTime(context.Context) error {
	f.clear++
	return nil
}

func TestHooksUpdateAndClearFreezeTime(t *testing.T) {
	orig := serviceAgent.ActiveHooks
	serviceAgent.RegisterHooks(&serviceAgent.AgentHook{})
	t.Cleanup(func() { serviceAgent.RegisterHooks(orig) })

	svc := &freezeRouteSvc{}
	a := &Agent{logger: zaptest.NewLogger(t), svc: svc}
	ts := time.Date(2024, 3, 2, 1, 2, 3, 4, time.UTC)

	before := httptest.NewRecorder()
	a.HandleBeforeSimulate(before, httptest.NewRequest(http.MethodPost, "/hooks/before-simulate", strings.NewReader(`{"timestamp":"`+ts.Format(time.RFC3339Nano)+`","testSetID":"test-set-0","testCaseName":"test-1"}`)))
	if before.Code != http.StatusOK {
		t.Fatalf("before status = %d, body=%q", before.Code, before.Body.String())
	}
	if !svc.set.Equal(ts) {
		t.Fatalf("freeze timestamp = %v, want %v", svc.set, ts)
	}

	after := httptest.NewRecorder()
	a.HandleAfterSimulate(after, httptest.NewRequest(http.MethodPost, "/hooks/after-simulate", strings.NewReader(`{"testSetID":"test-set-0","testCaseName":"test-1"}`)))
	if after.Code != http.StatusOK {
		t.Fatalf("after status = %d, body=%q", after.Code, after.Body.String())
	}
	if svc.clear != 1 {
		t.Fatalf("clear calls = %d, want 1", svc.clear)
	}
}

var _ serviceAgent.Service = (*freezeRouteSvc)(nil)
var _ serviceAgent.FreezeTimeService = (*freezeRouteSvc)(nil)
var _ coreAgent.FreezeTimeController = (*freezeRouteSvc)(nil)
