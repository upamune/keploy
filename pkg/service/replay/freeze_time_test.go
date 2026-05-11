package replay

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.keploy.io/server/v3/config"
	"go.keploy.io/server/v3/pkg/models"
	"go.uber.org/zap"
)

type freezeTimeInstrumentation struct{}

func (freezeTimeInstrumentation) Setup(context.Context, string, models.SetupOptions) error {
	return nil
}
func (freezeTimeInstrumentation) MockOutgoing(context.Context, models.OutgoingOptions) error {
	return nil
}
func (freezeTimeInstrumentation) Run(context.Context, models.RunOptions) models.AppError {
	return models.AppError{}
}
func (freezeTimeInstrumentation) GetErrorChannel() <-chan error { return nil }
func (freezeTimeInstrumentation) GetMockErrors(context.Context) ([]models.UnmatchedCall, error) {
	return nil, nil
}
func (freezeTimeInstrumentation) BeforeTestRun(context.Context, string) error { return nil }
func (freezeTimeInstrumentation) AfterTestRun(context.Context, string, []string, models.TestCoverage) error {
	return nil
}
func (freezeTimeInstrumentation) BeforeTestSetCompose(context.Context, string, string, bool) error {
	return nil
}
func (freezeTimeInstrumentation) BeforeSimulate(context.Context, *time.Time, string, string) error {
	return nil
}
func (freezeTimeInstrumentation) AfterSimulate(context.Context, string, string) error { return nil }
func (freezeTimeInstrumentation) GetConsumedMocks(context.Context) ([]models.MockState, error) {
	return nil, nil
}
func (freezeTimeInstrumentation) StoreMocks(context.Context, []*models.Mock, []*models.Mock) error {
	return nil
}
func (freezeTimeInstrumentation) UpdateMockParams(context.Context, models.MockFilterParams) error {
	return nil
}
func (freezeTimeInstrumentation) GetRecentAppLogs(context.Context) string { return "" }
func (freezeTimeInstrumentation) MakeAgentReadyForDockerCompose(context.Context) error {
	return nil
}
func (freezeTimeInstrumentation) NotifyGracefulShutdown(context.Context) error {
	return errors.ErrUnsupported
}

func TestHooksBeforeSimulateWritesFreezeTime(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEPLOY_FREEZE_TIME_FILE", filepath.Join(dir, "freeze-time"))

	h := &Hooks{
		logger:          zap.NewNop(),
		cfg:             &config.Config{Path: dir, Test: config.Test{FreezeTime: true}},
		instrumentation: freezeTimeInstrumentation{},
	}
	ts := time.Date(2024, 3, 2, 1, 2, 3, 4, time.UTC)
	if err := h.beforeSimulate(context.Background(), &ts, "test-set-0", "test-1"); err != nil {
		t.Fatalf("beforeSimulate returned error: %v", err)
	}

	if got := os.Getenv("KEPLOY_FREEZE_TIME"); got != ts.Format(time.RFC3339Nano) {
		t.Fatalf("KEPLOY_FREEZE_TIME = %q, want %q", got, ts.Format(time.RFC3339Nano))
	}
	body, err := os.ReadFile(filepath.Join(dir, "freeze-time"))
	if err != nil {
		t.Fatalf("read freeze-time file: %v", err)
	}
	if got, want := string(body), ts.Format(time.RFC3339Nano)+"\n"; got != want {
		t.Fatalf("freeze-time file = %q, want %q", got, want)
	}
}
