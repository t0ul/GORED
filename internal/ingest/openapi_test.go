package ingest

import "testing"

// ContractsFromOpenAPI must recover typed, required-tagged fields from the two spec dialects a
// vibe-coded app actually serves: OpenAPI 3.x (requestBody + $ref into components.schemas, plus
// query/path params) and Swagger 2.0 (a body param referencing definitions, with the type on the
// param). This is the ground truth that turns the exploit probes' field-name guesses into certainty.
func TestContractsFromOpenAPI3x(t *testing.T) {
	spec := []byte(`{
      "openapi": "3.0.0",
      "components": {"schemas": {"NewUser": {
        "type": "object",
        "required": ["email", "password"],
        "properties": {
          "email":    {"type": "string", "format": "email"},
          "password": {"type": "string"},
          "age":      {"type": "integer"},
          "admin":    {"type": "boolean"}
        }}}},
      "paths": {
        "/api/users/{id}": {
          "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
          "post": {
            "parameters": [{"name": "verbose", "in": "query", "schema": {"type": "boolean"}}],
            "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewUser"}}}}
          }
        }
      }}`)
	eps, err := ContractsFromOpenAPI(spec)
	if err != nil {
		t.Fatal(err)
	}
	ep := findEndpoint(t, eps, "POST", "/api/users/{id}")
	f := fieldMap(ep)

	if f["email"].Type != "email" || !f["email"].Required || f["email"].In != "body" {
		t.Errorf("email should be a required body field typed email (format), got %+v", f["email"])
	}
	if f["password"].Type != "string" || !f["password"].Required {
		t.Errorf("password should be required string, got %+v", f["password"])
	}
	if f["age"].Type != "number" { // integer maps to number
		t.Errorf("age integer should map to number, got %q", f["age"].Type)
	}
	if f["admin"].Type != "bool" {
		t.Errorf("admin boolean should map to bool, got %q", f["admin"].Type)
	}
	if f["email"].Required && f["age"].Required {
		t.Errorf("age is not in required[]; must not be marked required: %+v", f["age"])
	}
	if f["verbose"].In != "query" || f["verbose"].Type != "bool" {
		t.Errorf("verbose should be a query bool, got %+v", f["verbose"])
	}
	if f["id"].In != "path" || !f["id"].Required {
		t.Errorf("id should be a required path param, got %+v", f["id"])
	}
}

func TestContractsFromSwagger2(t *testing.T) {
	spec := []byte(`{
      "swagger": "2.0",
      "basePath": "/v1",
      "definitions": {"Login": {
        "type": "object",
        "required": ["username"],
        "properties": {"username": {"type": "string"}, "password": {"type": "string"}}
      }},
      "paths": {"/auth/login": {"post": {"parameters": [
        {"name": "body", "in": "body", "schema": {"$ref": "#/definitions/Login"}},
        {"name": "trace", "in": "query", "type": "boolean"}
      ]}}}}`)
	eps, err := ContractsFromOpenAPI(spec)
	if err != nil {
		t.Fatal(err)
	}
	ep := findEndpoint(t, eps, "POST", "/v1/auth/login") // basePath prepended
	f := fieldMap(ep)
	if f["username"].Type != "string" || !f["username"].Required || f["username"].In != "body" {
		t.Errorf("username should be a required string body field, got %+v", f["username"])
	}
	if f["password"].In != "body" || f["password"].Required {
		t.Errorf("password should be an optional body field, got %+v", f["password"])
	}
	if f["trace"].In != "query" || f["trace"].Type != "bool" {
		t.Errorf("trace should be a query bool (swagger 2.0 param type), got %+v", f["trace"])
	}
}

func findEndpoint(t *testing.T, eps []APIEndpoint, method, path string) APIEndpoint {
	t.Helper()
	for _, e := range eps {
		if e.Method == method && e.Path == path {
			return e
		}
	}
	t.Fatalf("endpoint %s %s not found in %+v", method, path, eps)
	return APIEndpoint{}
}

func fieldMap(ep APIEndpoint) map[string]APIField {
	m := map[string]APIField{}
	for _, f := range ep.Fields {
		m[f.Name] = f
	}
	return m
}
