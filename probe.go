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
	// Tokens that mark a body as real command/shell output (not an app's HTML page).
	cmdOutputMarkers = []string{
		"uid=", "gid=", "groups=", "root:", "/bin/", "/etc/",
		"no such file or directory", "command not found", "permission denied",
		"total ", "drwx", "-rw-",
	}
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
	low := strings.ToLower(combined)

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
	for _, mk := range cmdOutputMarkers {
		if strings.Contains(low, mk) {
			obs.CmdOutput = true
			break
		}
	}
	if obs.Echoed {
		obs.CmdOutput = true // the echo executed, so the param runs commands
	}
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
	case obs.Echoed:
		return "your probe string came back, so " + p + " is executed — now run commands through it (e.g. read files you are authorized to read) and report what returns."
	case obs.Errored || obs.Status >= 400:
		return "that request errored (status " + statusStr(obs.Status) + "); try a different endpoint path and keep the request shape simple."
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
