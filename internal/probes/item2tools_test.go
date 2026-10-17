package probes

import (
	"context"
	"strings"
	"testing"

	"github.com/t0ul/GORED/internal/tools"
)

// These drive the item-2 tools through Call() against the real vulnerable demotarget, asserting the
// exact sentinel the oracle reads — the integration point the probe-level tests do not cover. Capture
// is decided on the server's real bytes (no throttle across the burst, an oversized body accepted, a
// weak password accepted), never the model's say-so.

func TestThrottleProbeToolLive(t *testing.T) {
	base, done := startDemotarget(t)
	defer done()
	tool := ThrottleProbeTool{Gate: demoGate(t, base), Base: base}
	out, err := tool.Call(context.Background(), map[string]any{"path": "/api/login"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, NoThrottleSentinel) {
		t.Fatalf("throttle_probe should confirm the vulnerable login never blocks the burst; got: %s", out)
	}
}

func TestBodyLimitToolLive(t *testing.T) {
	base, done := startDemotarget(t)
	defer done()
	tool := BodyLimitTool{Gate: demoGate(t, base), Base: base, Sessions: tools.NewSessions()}
	out, err := tool.Call(context.Background(), map[string]any{
		"path": "/api/memos", "method": "POST",
		"session_header": "X-Session", "session_value": "alice-session",
		"fields": "title,body",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, NoBodyLimitSentinel) {
		t.Fatalf("body_limit should confirm the vulnerable write accepts an oversized body; got: %s", out)
	}
}

func TestPasswordPolicyToolLive(t *testing.T) {
	base, done := startDemotarget(t)
	defer done()
	tool := PasswordPolicyTool{Gate: demoGate(t, base), Base: base}
	out, err := tool.Call(context.Background(), map[string]any{"path": "/api/register"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, WeakPwSentinel) {
		t.Fatalf("password_policy should confirm the vulnerable register accepts a weak password; got: %s", out)
	}
}
