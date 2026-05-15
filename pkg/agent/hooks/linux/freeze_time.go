//go:build linux

// Package linux implements Linux-specific agent hooks.
package linux

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// SetFreezeAnchor seeds the Linux freeze-time controller before the user app
// starts. The actual eBPF time-rewrite programs consume the same state as
// SetFreezeTime; keeping the anchor in the controller closes startup gaps for
// libraries that read wall clock during process initialization.
func (h *Hooks) SetFreezeAnchor(_ context.Context, anchor time.Time) error {
	if h == nil || h.conf == nil || !h.conf.Test.FreezeTime || anchor.IsZero() {
		return nil
	}
	h.freezeMu.Lock()
	defer h.freezeMu.Unlock()

	h.freezeEnabled = true
	h.freezeAnchor = anchor.UTC()
	h.freezeTime = anchor.UTC()
	if err := h.updateFreezeConfig(h.freezeTime, true); err != nil {
		return err
	}
	h.logger.Debug("freeze-time anchor updated", zap.Time("anchor", h.freezeAnchor))
	return nil
}

// SetFreezeTime updates the wall-clock timestamp that Linux-native replay
// should expose to the user app for the next simulated testcase.
func (h *Hooks) SetFreezeTime(_ context.Context, timestamp time.Time) error {
	if h == nil || h.conf == nil || !h.conf.Test.FreezeTime || timestamp.IsZero() {
		return nil
	}
	h.freezeMu.Lock()
	defer h.freezeMu.Unlock()

	h.freezeEnabled = true
	h.freezeTime = timestamp.UTC()
	if err := h.updateFreezeConfig(h.freezeTime, true); err != nil {
		return err
	}
	h.logger.Debug("freeze-time timestamp updated", zap.Time("timestamp", h.freezeTime))
	return nil
}

// ClearFreezeTime disables testcase-scoped wall-clock rewriting after replay
// finishes simulating a testcase. The anchor is retained for diagnostics and
// for the next test run's startup window.
func (h *Hooks) ClearFreezeTime(_ context.Context) error {
	if h == nil || h.conf == nil || !h.conf.Test.FreezeTime {
		return nil
	}
	h.freezeMu.Lock()
	defer h.freezeMu.Unlock()

	h.freezeEnabled = false
	h.freezeTime = time.Time{}
	if err := h.updateFreezeConfig(time.Time{}, false); err != nil {
		return err
	}
	h.logger.Debug("freeze-time timestamp cleared")
	return nil
}

func (h *Hooks) freezeState() (enabled bool, anchor time.Time, timestamp time.Time) {
	h.freezeMu.RLock()
	defer h.freezeMu.RUnlock()
	return h.freezeEnabled, h.freezeAnchor, h.freezeTime
}
