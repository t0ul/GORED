package ingest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// APIPath is one route from an API spec: its path (with {param} templates intact) and
// the HTTP methods it declares. For an API-first app the spec is a more complete and
// reliable surface than crawling — it lists every route, including the {id} item
// endpoints a crawler never reaches, which is exactly what the id-swap step needs.
type APIPath struct {
	Path    string
	Methods []string
}

var httpMethodSet = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true, "options": true,
}

// PathsFromOpenAPI parses an OpenAPI 3.x or Swagger 2.0 spec (JSON) into its routes.
// Swagger 2.0's basePath is prepended. It reads only the paths/methods — enough to
// extend discovery — and ignores the rest of the spec.
func PathsFromOpenAPI(data []byte) ([]APIPath, error) {
	var spec struct {
		Swagger  string                                `json:"swagger"`
		OpenAPI  string                                `json:"openapi"`
		BasePath string                                `json:"basePath"`
		Paths    map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse openapi: %w", err)
	}
	if len(spec.Paths) == 0 {
		return nil, fmt.Errorf("openapi: no paths in spec (not a JSON OpenAPI/Swagger spec?)")
	}
	base := ""
	if strings.HasPrefix(spec.Swagger, "2") {
		base = strings.TrimRight(spec.BasePath, "/")
	}
	var out []APIPath
	for p, ops := range spec.Paths {
		var methods []string
		for m := range ops {
			if httpMethodSet[strings.ToLower(m)] {
				methods = append(methods, strings.ToUpper(m))
			}
		}
		if len(methods) == 0 {
			continue
		}
		sort.Strings(methods)
		full := base + p
		if !strings.HasPrefix(full, "/") {
			full = "/" + full
		}
		out = append(out, APIPath{Path: full, Methods: methods})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// MergeSpecPaths folds an API spec's routes into the hunt surface: collection paths
// join the testable resources, {param} paths join the item templates (for id-swap).
// Returns the merged resources and templates. Both are filtered and deduped.
func MergeSpecPaths(resources, templates []string, spec []APIPath) ([]string, []string) {
	haveR := map[string]bool{}
	for _, r := range resources {
		haveR[r] = true
	}
	haveT := map[string]bool{}
	for _, t := range templates {
		haveT[t] = true
	}
	for _, ap := range spec {
		p := ap.Path
		if !strings.HasPrefix(p, "/") {
			continue
		}
		if strings.ContainsAny(p, "{}") {
			if !haveT[p] && !strings.HasPrefix(p, "/api/auth/") {
				templates = append(templates, p)
				haveT[p] = true
			}
		} else if !haveR[p] && testablePath(p) {
			resources = append(resources, p)
			haveR[p] = true
		}
	}
	sort.Strings(resources)
	sort.Strings(templates)
	return resources, templates
}
