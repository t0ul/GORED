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
