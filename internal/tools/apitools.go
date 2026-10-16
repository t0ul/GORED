package tools

import (
	"context"
	"fmt"
	"strings"
)

// APIRequestTool (api_request) is the JSON-API exploit primitive: an arbitrary HTTP request
// with a method, headers and a body, all through the Egress gate. The GET-only http_request
// cannot express an authenticated POST/PUT, a forged Authorization header, or an id-swapped
// read as another identity — the moves that land broken-authorization, mass-assignment and
// JWT bugs. The tool is generic: it bakes in no endpoint, header or payload for the target;
// the agent (or the pilot) supplies them from what it discovered.
type APIRequestTool struct {
	Gate *Gate
	Base string
}

func (APIRequestTool) Name() string { return "api_request" }
func (APIRequestTool) Describe() string {
	return `Make an HTTP request with a method, headers and a body (for JSON APIs and authenticated calls). ` +
		`args: {"method":"GET|POST|PUT|PATCH|DELETE","path":"/api/notes/1000","headers":{"X-Session":"<token>"},"body":"{...}"}. ` +
		`Use it to send a session/Authorization header, read a record that belongs to another user by changing an id in the path, ` +
		`or POST/PUT a JSON body with an extra privileged field. Returns the status code and the response body.`
}

func (t APIRequestTool) Call(ctx context.Context, args map[string]any) (string, error) {
	u, err := resolveURL(args, t.Base)
	if err != nil {
		return "", fmt.Errorf("api_request: %w", err)
	}
	method := strings.ToUpper(asString(args["method"]))
	if method == "" {
		method = "GET"
	}
	headers := map[string]string{}
	placeholder := ""
	if h, ok := args["headers"].(map[string]any); ok {
		for k, v := range h {
			val := asString(v)
			headers[k] = val
			// A value like "<token>" or "<session_value>" is an unfilled placeholder, not a real
			// credential — flag it so the model substitutes the actual value it read from the app.
			if strings.HasPrefix(strings.TrimSpace(val), "<") && strings.HasSuffix(strings.TrimSpace(val), ">") {
				placeholder = k
			}
		}
	}
	body := asString(args["body"])
	status, respBody, err := t.Gate.Request(ctx, method, strings.ReplaceAll(u, " ", "%20"), headers, body)
	if err != nil {
		return "", fmt.Errorf("api_request: %w", err)
	}
	// A short, generic nudge on the statuses that usually mean "close, but adjust one thing", so
	// the model self-corrects instead of repeating the same call.
	hint := ""
	switch status {
	case 401, 403:
		hint = "\n(hint: authorize this call — send the session/Authorization header the app documents, or try another identity)"
	case 404:
		hint = "\n(hint: no such path — recon with http_request and use a path you actually found)"
	case 405:
		hint = "\n(hint: wrong method for this path — try the method the endpoint expects, e.g. GET vs POST/PUT)"
	}
	// A placeholder header value is the likeliest reason for a 401/403, so lead with that fix.
	if placeholder != "" {
		hint = fmt.Sprintf("\n(hint: header %q is a placeholder (%s) — substitute the real value you read from the app, not a literal <...>)", placeholder, headers[placeholder]) + hint
	}
	return fmt.Sprintf("HTTP %d\n%s%s", status, respBody, hint), nil
}

// EgressAuthorities exposes the gate's allowlist, so the loop's egress-denied beacon can log
// it when api_request is the tool a stage carries for the beacon.
func (t APIRequestTool) EgressAuthorities() []string {
	if t.Gate == nil || t.Gate.Egress() == nil {
		return nil
	}
	return t.Gate.Egress().Authorities()
}
