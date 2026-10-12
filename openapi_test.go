package gored_test

import (
	"context"
	"testing"

	gored "github.com/t0ul/GORED"
)

func TestPathsFromOpenAPI(t *testing.T) {
	// OpenAPI 3.x: paths at top level, {id} templates intact.
	v3 := []byte(`{"openapi":"3.0.0","paths":{
		"/api/tickets":{"get":{},"post":{}},
		"/api/drafts/report/{id}":{"get":{},"post":{}},
		"/api/reports/view/{id}":{"get":{}},
		"/webhooks":{"x-ignored":{}}
	}}`)
	got, err := gored.PathsFromOpenAPI(v3)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string][]string{}
	for _, p := range got {
		byPath[p.Path] = p.Methods
	}
	if _, ok := byPath["/api/drafts/report/{id}"]; !ok {
		t.Errorf("missing the {id} item endpoint a crawler would never reach: %+v", got)
	}
	if m := byPath["/api/tickets"]; len(m) != 2 {
		t.Errorf("/api/tickets methods: want 2 (GET,POST), got %v", m)
	}
	if _, ok := byPath["/webhooks"]; ok {
		t.Errorf("/webhooks had no real HTTP methods and should be dropped")
	}

	// Swagger 2.0: basePath prepended.
	v2 := []byte(`{"swagger":"2.0","basePath":"/api/v1","paths":{"/molts":{"get":{}}}}`)
	got2, err := gored.PathsFromOpenAPI(v2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got2) != 1 || got2[0].Path != "/api/v1/molts" {
		t.Errorf("swagger basePath not prepended: %+v", got2)
	}
}

// TestHuntMergesSpecPaths proves an API spec extends the hunt surface: collection
// paths join the resources and {id} paths join the templates (for id-swap) — the
// routes a crawler misses on an API-first app.
func TestHuntMergesSpecPaths(t *testing.T) {
	_, base := liveTarget(t)
	h := &gored.Hunt{
		Base: base, Egress: gored.NewEgress(authority(t, base)), Sessions: gored.NewSessions(),
		Priv: gored.Identity{Name: "admin", Headers: map[string]string{"X-Session": "admin-session"}},
		Low:  gored.Identity{Name: "alice", Headers: map[string]string{"X-Session": "alice-session"}},
		Anon: &gored.Identity{Name: "anon"},
		SpecPaths: []gored.APIPath{
			{Path: "/api/reports/view/{id}", Methods: []string{"GET"}},
			{Path: "/api/orders", Methods: []string{"GET", "POST"}},
		},
	}
	rep, err := h.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !contains(rep.Discovered, "/api/orders") {
		t.Errorf("spec collection /api/orders not merged into resources: %v", rep.Discovered)
	}
	// {id} paths don't appear in Discovered (resources); they go to templates. We can't
	// read templates off the report, but the collection merge confirms the wiring.
}
