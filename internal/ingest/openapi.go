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

// APIField is one request parameter declared by a spec: its name, mapped type, whether it is
// required, and where it rides (body|query|path|header). It is the typed detail PathsFromOpenAPI
// throws away — exactly what the exploit probes need to build a schema-valid request.
type APIField struct {
	Name     string
	Type     string // string|number|bool|email|array|object|unknown
	Required bool
	In       string // body|query|path|header
}

// APIEndpoint is one (method, path) operation with its reverse-engineered fields.
type APIEndpoint struct {
	Method string
	Path   string
	Fields []APIField
}

// oaSchema / oaParam / oaOp / oaPathItem / oaSpec are the minimal OpenAPI 3.x + Swagger 2.0 shapes
// ContractsFromOpenAPI decodes. They cover the common cases (JSON requestBody, parameters, and one
// level of $ref into components.schemas / definitions); anything exotic degrades to type "unknown".
type oaSchema struct {
	Ref        string              `json:"$ref"`
	Type       string              `json:"type"`
	Format     string              `json:"format"`
	Required   []string            `json:"required"`
	Properties map[string]oaSchema `json:"properties"`
}

type oaParam struct {
	Name     string    `json:"name"`
	In       string    `json:"in"`
	Required bool      `json:"required"`
	Type     string    `json:"type"` // Swagger 2.0 carries the type on the param
	Format   string    `json:"format"`
	Schema   *oaSchema `json:"schema"` // OpenAPI 3.x, and Swagger 2.0 body params
}

type oaOp struct {
	Parameters  []oaParam `json:"parameters"`
	RequestBody *struct {
		Content map[string]struct {
			Schema oaSchema `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
}

type oaPathItem struct {
	Parameters []oaParam `json:"parameters"` // path-level params shared by every operation
}

type oaSpec struct {
	Swagger    string `json:"swagger"`
	BasePath   string `json:"basePath"`
	Components struct {
		Schemas map[string]oaSchema `json:"schemas"`
	} `json:"components"`
	Definitions map[string]oaSchema        `json:"definitions"`
	Paths       map[string]json.RawMessage `json:"paths"`
}

// ContractsFromOpenAPI parses an OpenAPI 3.x / Swagger 2.0 spec into per-operation field contracts:
// typed body fields (from requestBody or a Swagger body param, with required flags), and query/path/
// header params. This is the richer counterpart of PathsFromOpenAPI, which stays paths-only.
func ContractsFromOpenAPI(data []byte) ([]APIEndpoint, error) {
	var sp oaSpec
	if err := json.Unmarshal(data, &sp); err != nil {
		return nil, fmt.Errorf("parse openapi: %w", err)
	}
	if len(sp.Paths) == 0 {
		return nil, fmt.Errorf("openapi: no paths in spec (not a JSON OpenAPI/Swagger spec?)")
	}
	base := ""
	if strings.HasPrefix(sp.Swagger, "2") {
		base = strings.TrimRight(sp.BasePath, "/")
	}
	var out []APIEndpoint
	for p, raw := range sp.Paths {
		var shared oaPathItem
		_ = json.Unmarshal(raw, &shared)
		var ops map[string]json.RawMessage
		_ = json.Unmarshal(raw, &ops)
		full := base + p
		if !strings.HasPrefix(full, "/") {
			full = "/" + full
		}
		for m, opRaw := range ops {
			if !httpMethodSet[strings.ToLower(m)] {
				continue
			}
			var op oaOp
			_ = json.Unmarshal(opRaw, &op)
			fields := map[string]APIField{}
			add := func(f APIField) { fields[f.In+"\x00"+f.Name] = f }
			for _, prm := range append(append([]oaParam{}, shared.Parameters...), op.Parameters...) {
				if strings.EqualFold(prm.In, "body") && prm.Schema != nil { // Swagger 2.0 body param
					for _, bf := range sp.bodyFields(*prm.Schema) {
						add(bf)
					}
					continue
				}
				if f, ok := sp.paramField(prm); ok {
					add(f)
				}
			}
			if op.RequestBody != nil { // OpenAPI 3.x
				if sch, ok := pickJSONSchema(op.RequestBody.Content); ok {
					for _, bf := range sp.bodyFields(sch) {
						add(bf)
					}
				}
			}
			fs := make([]APIField, 0, len(fields))
			for _, f := range fields {
				fs = append(fs, f)
			}
			sort.Slice(fs, func(i, j int) bool {
				if fs[i].In != fs[j].In {
					return fs[i].In < fs[j].In
				}
				return fs[i].Name < fs[j].Name
			})
			out = append(out, APIEndpoint{Method: strings.ToUpper(m), Path: full, Fields: fs})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out, nil
}

// bodyFields expands an object schema (resolving a $ref first) into typed, required-tagged body fields.
func (sp *oaSpec) bodyFields(s oaSchema) []APIField {
	s = sp.resolve(s)
	req := map[string]bool{}
	for _, r := range s.Required {
		req[r] = true
	}
	out := make([]APIField, 0, len(s.Properties))
	for name, ps := range s.Properties {
		out = append(out, APIField{Name: name, Type: oaType(sp.resolve(ps)), Required: req[name], In: "body"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// paramField maps a non-body parameter to an APIField; ok=false for a body param (handled via schema).
func (sp *oaSpec) paramField(p oaParam) (APIField, bool) {
	in := strings.ToLower(p.In)
	if in == "body" {
		return APIField{}, false
	}
	if in == "formdata" {
		in = "body"
	}
	if in != "query" && in != "path" && in != "header" && in != "body" {
		return APIField{}, false
	}
	typ := "unknown"
	if p.Type != "" {
		typ = oaType(oaSchema{Type: p.Type, Format: p.Format})
	} else if p.Schema != nil {
		typ = oaType(sp.resolve(*p.Schema))
	}
	return APIField{Name: p.Name, Type: typ, Required: p.Required, In: in}, true
}

// resolve follows a $ref (up to a small depth, guarding cycles) into components.schemas/definitions.
func (sp *oaSpec) resolve(s oaSchema) oaSchema {
	seen := map[string]bool{}
	for s.Ref != "" && !seen[s.Ref] {
		seen[s.Ref] = true
		name := s.Ref[strings.LastIndex(s.Ref, "/")+1:]
		if r, ok := sp.schemas()[name]; ok {
			s = r
		} else {
			break
		}
	}
	return s
}

// schemas merges Swagger 2.0 definitions and OpenAPI 3.x components.schemas for $ref resolution.
func (sp *oaSpec) schemas() map[string]oaSchema {
	m := make(map[string]oaSchema, len(sp.Definitions)+len(sp.Components.Schemas))
	for k, v := range sp.Definitions {
		m[k] = v
	}
	for k, v := range sp.Components.Schemas {
		m[k] = v
	}
	return m
}

// pickJSONSchema returns the application/json request-body schema (else the first content type).
func pickJSONSchema(content map[string]struct {
	Schema oaSchema `json:"schema"`
}) (oaSchema, bool) {
	if c, ok := content["application/json"]; ok {
		return c.Schema, true
	}
	for _, c := range content {
		return c.Schema, true
	}
	return oaSchema{}, false
}

// oaType maps an OpenAPI/Swagger type (+ format) to the probe-facing type vocabulary.
func oaType(s oaSchema) string {
	if s.Type == "string" && s.Format == "email" {
		return "email"
	}
	switch s.Type {
	case "integer", "number":
		return "number"
	case "boolean":
		return "bool"
	case "string":
		return "string"
	case "array":
		return "array"
	case "object":
		return "object"
	}
	return "unknown"
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
