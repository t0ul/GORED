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
	if h, ok := args["headers"].(map[string]any); ok {
		for k, v := range h {
			headers[k] = asString(v)
		}
	}
	body := asString(args["body"])
	status, respBody, err := t.Gate.Request(ctx, method, strings.ReplaceAll(u, " ", "%20"), headers, body)
	if err != nil {
		return "", fmt.Errorf("api_request: %w", err)
	}
	return fmt.Sprintf("HTTP %d\n%s", status, respBody), nil
}

// EgressAuthorities exposes the gate's allowlist, so the loop's egress-denied beacon can log
// it when api_request is the tool a stage carries for the beacon.
func (t APIRequestTool) EgressAuthorities() []string {
	if t.Gate == nil || t.Gate.Egress() == nil {
		return nil
	}
	return t.Gate.Egress().Authorities()
}
