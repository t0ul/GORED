package eva

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/GORED/internal/tools"
	"github.com/t0ul/GORED/store"
)

// reconOpenAPI must fetch a served spec and fold its FULL typed schema into project memory at the
// openapi (highest) precedence — the integration point between the parser and the contract store.
// This is what hands the exploit probes ground-truth types/required instead of guessed names.
func TestReconOpenAPIIngestToStore(t *testing.T) {
	const spec = `{
      "openapi": "3.0.0",
      "components": {"schemas": {"Widget": {
        "type": "object",
        "required": ["name"],
        "properties": {"name": {"type": "string"}, "qty": {"type": "integer"}}
      }}},
      "paths": {"/api/widgets": {"post": {
        "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Widget"}}}}
      }}}}`

	mux := http.NewServeMux()
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, spec)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	st, err := store.Open(filepath.Join(t.TempDir(), "o.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Classify = func(m, p string) string { return classifyEndpoint(m, p).class }

	s := &Server{store: st}
	tg := store.Target{Name: "app", Base: ts.URL}
	s.reconOpenAPI(context.Background(), tg, tools.NewSessions(), tools.NewEgress(strings.TrimPrefix(ts.URL, "http://")))

	rows, err := st.ListSurface("app")
	if err != nil {
		t.Fatal(err)
	}
	var widget *store.SurfaceRow
	for i := range rows {
		if rows[i].Method == "POST" && rows[i].Path == "/api/widgets" {
			widget = &rows[i]
		}
	}
	if widget == nil {
		t.Fatalf("POST /api/widgets should be ingested from the spec; got %+v", rows)
	}
	if widget.Source != "openapi" {
		t.Errorf("source should be openapi, got %q", widget.Source)
	}
	if widget.Contract == nil {
		t.Fatal("ingested endpoint should carry a contract")
	}
	byName := map[string]store.FieldSpec{}
	for _, f := range widget.Contract.Fields {
		byName[f.Name] = f
	}
	if byName["name"].Type != "string" || !byName["name"].Required {
		t.Errorf("name should be a required string from the spec, got %+v", byName["name"])
	}
	if byName["qty"].Type != "number" || byName["qty"].Required {
		t.Errorf("qty should be an optional number from the spec, got %+v", byName["qty"])
	}
}
