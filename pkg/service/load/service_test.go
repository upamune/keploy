package load

import (
	"testing"
	"time"
)

func TestSummarizeComputesPercentiles(t *testing.T) {
	ch := make(chan time.Duration, 5)
	for _, v := range []time.Duration{50, 10, 30, 20, 40} {
		ch <- v * time.Millisecond
	}
	close(ch)

	s := summarize(ch, 5, 1, time.Second)
	if s.Requests != 5 || s.Failures != 1 {
		t.Fatalf("summary counts = %d/%d, want 5/1", s.Requests, s.Failures)
	}
	if s.Min != 10*time.Millisecond || s.Max != 50*time.Millisecond {
		t.Fatalf("min/max = %s/%s", s.Min, s.Max)
	}
	if s.P50 != 30*time.Millisecond {
		t.Fatalf("p50 = %s, want 30ms", s.P50)
	}
	if s.P95 != 40*time.Millisecond {
		t.Fatalf("p95 = %s, want 40ms", s.P95)
	}
}
