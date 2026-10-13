package gored

import (
	"strings"
	"testing"
)

func TestParseProbe(t *testing.T) {
	// Echoed probe -> injected + command output, status 200.
	obs := ParseProbe("RCEPROBE\n", "RCEPROBE", "")
	if !obs.Echoed || !obs.CmdOutput || obs.Status != 200 || obs.Errored {
		t.Errorf("echoed probe misread: %+v", obs)
	}
	// id output -> command output even without a nonce.
	obs = ParseProbe("uid=0(root) gid=0(root)", "", "")
	if obs.Echoed || !obs.CmdOutput {
		t.Errorf("id output misread: %+v", obs)
	}
	// wget 400 error -> errored, status parsed from the text.
	obs = ParseProbe("", "", "wget: server returned error: HTTP/1.1 400 Bad Request")
	if !obs.Errored || obs.Status != 400 {
		t.Errorf("error response misread: %+v", obs)
	}
	// A plain HTML page with no markers and no echo -> 200, not command output.
	obs = ParseProbe("<!doctype html><title>Notes</title>", "XYZ", "")
	if obs.Echoed || obs.CmdOutput || obs.Status != 200 {
		t.Errorf("html page misread: %+v", obs)
	}
}

func TestReflectHintNeverLeaksLocation(t *testing.T) {
	// Whatever the observation, the hint must not name the vulnerable endpoint/param
	// or a flag — it is methodology only.
	for _, obs := range []ProbeObservation{
		{Echoed: true, CmdOutput: true, Status: 200},
		{Errored: true, Status: 400},
		{Status: 200},
		{},
	} {
		h := strings.ToLower(ReflectHint(obs, "cmd"))
		for _, banned := range []string{"/exec", "flag-in-container", "brig-host", "gored{"} {
			if strings.Contains(h, banned) {
				t.Errorf("hint leaked %q: %s", banned, h)
			}
		}
		if h == "" {
			t.Error("empty hint")
		}
	}
}

func TestReflectHintGuidesByState(t *testing.T) {
	if !strings.Contains(ReflectHint(ProbeObservation{Echoed: true}, "cmd"), "executed") {
		t.Error("echoed hint should say the param is executed")
	}
	if !strings.Contains(strings.ToLower(ReflectHint(ProbeObservation{Status: 404, Errored: true}, "")), "different") {
		t.Error("error hint should suggest a different endpoint/param")
	}
}
