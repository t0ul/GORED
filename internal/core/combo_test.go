package core

import "testing"

func TestActionKeyCanonical(t *testing.T) {
	// All finish claims collapse to one key regardless of the claimed flag.
	if actionKey(action{Done: true, Flag: "GORED{a}"}) != "done" ||
		actionKey(action{Done: true, Flag: "GORED{b}"}) != "done" {
		t.Fatal("done actions must share one vote key")
	}
	// Same tool + same args => same key, independent of map construction order
	// (encoding/json sorts keys).
	k1 := actionKey(action{Tool: "http_request", Args: map[string]any{"method": "GET", "path": "/x"}})
	k2 := actionKey(action{Tool: "http_request", Args: map[string]any{"path": "/x", "method": "GET"}})
	if k1 != k2 {
		t.Fatalf("args order changed the key: %q vs %q", k1, k2)
	}
	// Different args => different key.
	k3 := actionKey(action{Tool: "http_request", Args: map[string]any{"path": "/y"}})
	if k1 == k3 {
		t.Fatal("different args must not share a vote key")
	}
	// Tool call and done never collide.
	if k1 == "done" {
		t.Fatal("tool key collided with done")
	}
}
