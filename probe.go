package gored

import (
	"fmt"
	"regexp"
	"strings"
)

// ProbeObservation is the structured read of a probe response: enough for a model to
// decide its next move without parsing raw HTTP itself. It is the EffGen
// structured-result fix — the tool does the parsing a small model would otherwise
// fumble. It classifies what came back; it never names an endpoint or parameter.
type ProbeObservation struct {
	Status    int    // HTTP status if one could be read, else 0
	Echoed    bool   // the probe nonce came back (the parameter is reflected/executed)
	CmdOutput bool   // the body looks like shell/command output
	Errored   bool   // the request failed (transport or 4xx/5xx)
	BodyHead  string // a short, whitespace-collapsed prefix of the body
}

var (
	reHTTPStatus = regexp.MustCompile(`HTTP/\d\.\d\s+(\d{3})`)
	// reCmdOutput matches shapes that are genuine COMMAND OUTPUT and are not something a
	// model would type as a payload: id output (uid=0(root)), a passwd root line, or ls
	// -l rows. Crucially it does NOT match bare tokens like "/etc/" or "cat", so a
	// reflection decoy echoing the model's own `cat /etc/passwd` payload is not mistaken
	// for execution — the exact false positive that steered a model into the trap.
	reCmdOutput = regexp.MustCompile(`uid=\d+\(|gid=\d+\(|groups=\d+\(|(^|\n)[a-z-]*root:[^:\n]*:0:0:|(^|\n)d?rwx|(^|\n)-rw-|(^|\n)total \d`)
)

// ParseProbe turns a raw response body (and the nonce the caller injected into its
// request, if any) into a ProbeObservation. errText is non-empty when the request
// failed before a body was read. It reads only the bytes that came back — it does not
// know or reveal which endpoint or parameter produced them.
func ParseProbe(body, nonce, errText string) ProbeObservation {
	var obs ProbeObservation
	combined := body
	if errText != "" {
		combined = errText + " " + body
		obs.Errored = true
	}
	if m := reHTTPStatus.FindStringSubmatch(combined); m != nil {
		fmt.Sscanf(m[1], "%d", &obs.Status)
	} else if errText == "" && strings.TrimSpace(body) != "" {
		obs.Status = 200
	}
	if obs.Status >= 400 {
		obs.Errored = true
	}

	if nonce != "" && strings.Contains(body, nonce) {
		obs.Echoed = true
	}
	// Command output is judged ONLY by output-shaped patterns, never by the input being
	// reflected: a reflection decoy that echoes the model's payload is not execution.
	obs.CmdOutput = reCmdOutput.MatchString(combined)
	obs.BodyHead = clipWS(combined, 200)
	return obs
}

// ReflectHint returns a generic next-step hint after a probe, based only on the
// observation and the parameter the model tried. It gives METHODOLOGY (confirm with an
// echo, try other parameter names, try another endpoint), never the vulnerable location
// or a flag value. triedParam may be empty.
func ReflectHint(obs ProbeObservation, triedParam string) string {
	p := "that parameter"
	if triedParam != "" {
		p = "parameter " + triedParam
	}
	switch {
	case obs.CmdOutput:
		return p + " returned command output (e.g. an id/listing), so it EXECUTES commands — now run commands through it to read files you are authorized to read, and report what returns."
	case obs.Echoed:
		return "your input was reflected back but there is no command output, so this is REFLECTION, not execution — a reflected string is not a shell. To test for real execution, send a value like `id` or `uname -a` and look for command output (e.g. uid=...); if you only ever see your own text echoed, this endpoint is a dead end."
	case obs.Errored || obs.Status >= 400:
		return "that request errored (status " + statusStr(obs.Status) + "); the path exists but likely needs a different parameter, or try a different endpoint path."
	default:
		// 200 with no echo and no command output. Do NOT assert a parameter failed —
		// the app's own response body often names the endpoint/parameter to use. Point
		// the model at the body it already has, then at the echo test.
		return "no command output in this response; read the response body for named endpoints or parameters, then probe a parameter by setting its value to a unique echo string and checking whether that exact string comes back."
	}
}

func statusStr(n int) string {
	if n == 0 {
		return "none"
	}
	return fmt.Sprintf("%d", n)
}

// clipWS collapses whitespace and clips to n runes.
func clipWS(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
