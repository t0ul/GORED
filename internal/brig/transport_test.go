package brig

import "testing"

// The live Fetch/Detonate paths require a running Brig; they are exercised by the
// gored-reconsweep live run. Offline, assert the pure, deterministic parts (and the
// compile-time tools.Transport satisfaction via the var in transport.go).
func TestTransportDescribeAndDefaults(t *testing.T) {
	tr := Transport{Bridge: "127.0.0.1:5050"}
	if got := tr.Describe(); got != "brig(127.0.0.1:5050)" {
		t.Errorf("Describe = %q, want brig(127.0.0.1:5050)", got)
	}
	if tr.traceID() != "gored-tool" {
		t.Errorf("default traceID = %q, want gored-tool", tr.traceID())
	}
	if (Transport{TraceID: "recon"}).traceID() != "recon" {
		t.Error("explicit TraceID must be preserved")
	}
	if tr.fetchClient().Timeout == 0 || tr.scanClient().Timeout == 0 {
		t.Error("default clients must carry a timeout")
	}
	if tr.scanClient().Timeout <= tr.fetchClient().Timeout {
		t.Error("the scan client should allow longer than the fetch client (scanners fire many payloads)")
	}
}
