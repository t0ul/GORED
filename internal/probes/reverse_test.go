package probes

import "testing"

// reverseAPIShapes must reconstruct the method, path and body fields straight from readable client
// JS — the way a vibe-coded app's own code reveals its private API. The fixtures below are the real
// shapes of RiskRancher's static JS (used here only as test input; nothing app-specific is compiled
// into the tool).
func TestReverseAPIShapes(t *testing.T) {
	js := `
	fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" },
	  body: JSON.stringify({ email: document.getElementById("email").value, password: pw }) });
	fetch('/api/tickets/review-link', { method: 'POST', body: JSON.stringify({ ticket_ids: ids }) });
	fetch(` + "`" + `/api/tickets/${id}/review` + "`" + `, { method: 'PATCH', body: JSON.stringify({ action: 'Deny' }) });
	fetch(` + "`" + `/api/admin/users/${uid}` + "`" + `, { method: 'DELETE' });
	fetch('/api/adapters', { method: 'POST', body: JSON.stringify(data) });
	fetch('/api/tickets?status=open');
	axios.post("/api/orders", { sku: s, qty: n });
	$.post('/api/comments', { text: t });
	$.ajax({ url: "/api/profile", type: "PUT", data: { role: r } });
	api.delete(` + "`" + `/api/sessions/${sid}` + "`" + `);
	const u = params.get("ignore-me");
	`
	got := ReverseAPIShapes(js)
	byPath := map[string]APIShape{}
	for _, s := range got {
		byPath[s.Path] = s
	}

	want := []struct {
		path, method string
		fields       []string
	}{
		{"/api/auth/login", "POST", []string{"email", "password"}},
		{"/api/tickets/review-link", "POST", []string{"ticket_ids"}},
		{"/api/tickets/{id}/review", "PATCH", []string{"action"}}, // ${id} normalized
		{"/api/admin/users/{id}", "DELETE", nil},                  // ${uid} normalized, no body
		{"/api/adapters", "POST", nil},                            // opaque var body -> method+path only
		{"/api/tickets", "GET", nil},                              // no method -> GET, query stripped
		{"/api/orders", "POST", []string{"sku", "qty"}},           // axios.post, positional data arg
		{"/api/comments", "POST", []string{"text"}},               // jQuery $.post
		{"/api/profile", "PUT", []string{"role"}},                 // $.ajax config object (type -> method)
		{"/api/sessions/{id}", "DELETE", nil},                     // wrapped client verb + template id
	}
	for _, w := range want {
		s, ok := byPath[w.path]
		if !ok {
			t.Errorf("missing shape for %s; got %+v", w.path, got)
			continue
		}
		if s.Method != w.method {
			t.Errorf("%s: method = %q, want %q", w.path, s.Method, w.method)
		}
		if len(s.Fields) != len(w.fields) {
			t.Errorf("%s: fields = %v, want %v", w.path, s.Fields, w.fields)
			continue
		}
		for i := range w.fields {
			if s.Fields[i] != w.fields[i] {
				t.Errorf("%s: field[%d] = %q, want %q", w.path, i, s.Fields[i], w.fields[i])
			}
		}
	}
}

// With LITERAL body values the static parser also infers field types, and query-string keys are
// captured as query params (not dropped) — the typed-RE + query enrichment. Variable/expression
// values stay untyped (OpenAPI fills those when a spec is served).
func TestReverseAPIShapesTypesAndQuery(t *testing.T) {
	js := `
	fetch("/api/signup", { method: "POST", body: JSON.stringify({ email: "a@b.com", age: 30, admin: false, name: n }) });
	fetch("/api/search?term=x&limit=10&term=y");
	`
	got := ReverseAPIShapes(js)
	byPath := map[string]APIShape{}
	for _, s := range got {
		byPath[s.Path] = s
	}

	signup, ok := byPath["/api/signup"]
	if !ok {
		t.Fatalf("missing /api/signup shape; got %+v", got)
	}
	if signup.Types["email"] != "string" { // a string literal: static can't know it's an email, only a string
		t.Errorf("email literal should infer string, got %q", signup.Types["email"])
	}
	if signup.Types["age"] != "number" {
		t.Errorf("age literal should infer number, got %q", signup.Types["age"])
	}
	if signup.Types["admin"] != "bool" {
		t.Errorf("admin literal should infer bool, got %q", signup.Types["admin"])
	}
	if _, typed := signup.Types["name"]; typed {
		t.Errorf("name is a variable; it must stay untyped, got %q", signup.Types["name"])
	}

	search, ok := byPath["/api/search"]
	if !ok {
		t.Fatalf("missing /api/search shape; got %+v", got)
	}
	gotQ := map[string]bool{}
	for _, q := range search.Query {
		gotQ[q] = true
	}
	if !gotQ["term"] || !gotQ["limit"] {
		t.Errorf("query keys term+limit should be captured, got %v", search.Query)
	}
	if len(search.Query) != 2 {
		t.Errorf("duplicate query key must dedup to 2 keys, got %v", search.Query)
	}
}
