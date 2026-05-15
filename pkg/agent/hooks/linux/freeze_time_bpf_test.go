//go:build linux

package linux

import (
	"testing"
	"time"
)

func TestFreezeConfigFor(t *testing.T) {
	ts := time.Date(2024, 3, 2, 1, 2, 3, 456789123, time.FixedZone("JST", 9*60*60))

	cfg := freezeConfigFor(ts, true)
	if cfg.Enabled != 1 {
		t.Fatalf("Enabled = %d, want 1", cfg.Enabled)
	}
	if cfg.Sec != uint64(ts.UTC().Unix()) {
		t.Fatalf("Sec = %d, want %d", cfg.Sec, ts.UTC().Unix())
	}
	if cfg.Nsec != 456789123 {
		t.Fatalf("Nsec = %d, want 456789123", cfg.Nsec)
	}

	disabled := freezeConfigFor(ts, false)
	if disabled.Enabled != 0 {
		t.Fatalf("disabled Enabled = %d, want 0", disabled.Enabled)
	}
}
