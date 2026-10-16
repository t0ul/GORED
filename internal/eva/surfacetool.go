package eva

import (
	"context"
	"fmt"
	"strings"

	"github.com/t0ul/GORED/store"
)

// surfaceSaveTool lets the model deliberately record an endpoint it found to the target's project
// memory, attributed to the model that found it. It replaces guessing the model's map by scraping
// the trace after the fact: the weapon reports its own discoveries, and because the row carries the
// model name, each model's surface stays distinct and comparable across a research run. Write-only
// to the surface table — it performs no network I/O (the model reaches the app through
// http_request / discover); it cannot assert a capture, only persist what was observed.
type surfaceSaveTool struct {
	store  *store.Store
	target string
	model  string
}

func (surfaceSaveTool) Name() string { return "save_surface" }

func (surfaceSaveTool) Describe() string {
	return `Record an endpoint you found on the target so it persists to project memory (attributed to your model) and seeds later passes. args: {"method":"GET|POST|PUT|PATCH|DELETE","path":"/api/...","note":"what it is / why it matters"}. Call it for every notable route you discover — collections, {id} object endpoints, admin, uploads, auth, anything touching data.`
}

func (t surfaceSaveTool) Call(ctx context.Context, args map[string]any) (string, error) {
	if t.store == nil || t.target == "" {
		return "", fmt.Errorf("save_surface: no project store bound to this run")
	}
	path := strings.TrimSpace(asStr(args["path"]))
	if path == "" {
		return "", fmt.Errorf("save_surface: a path is required, e.g. {\"path\":\"/api/users/{id}\"}")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	method := strings.ToUpper(strings.TrimSpace(asStr(args["method"])))
	if method == "" {
		method = "GET"
	}
	note := strings.TrimSpace(asStr(args["note"]))
	if note == "" {
		note = "model-reported"
	}
	if err := t.store.SaveSurface(t.target, t.model, method, path, note); err != nil {
		return "", fmt.Errorf("save_surface: %w", err)
	}
	return fmt.Sprintf("saved %s %s to project memory (model %q)", method, path, t.model), nil
}
