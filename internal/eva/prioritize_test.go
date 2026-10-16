package eva

import "testing"

// classifyEndpoint routes by path+method shape into the right tier/class, generically.
func TestClassifyEndpoint(t *testing.T) {
	cases := []struct {
		method, path string
		tier         int
		class        string
	}{
		{"GET", "/api/tickets/{id}", 1, "idor"},
		{"GET", "/molt/view/3KmQwv6zU6zicG9", 1, "idor"},
		{"POST", "/krab/login", 1, "auth"},
		{"GET", "/admin", 1, "admin"},
		{"GET", "/api/config", 3, "info"},
		{"GET", "/api/fetch?url=x", 3, "ssrf"},
		{"POST", "/api/images/upload", 2, "upload"},
		{"GET", "/api/reports/view/7", 2, "export"},
		{"GET", "/search?q=x", 2, "search"},
		{"POST", "/api/ingest/csv", 2, "ingest"},
		{"PUT", "/api/profile", 2, "write"},
		{"GET", "/api/tickets", 1, "idor"}, // bare /api collection -> id-swap candidate
		{"GET", "/about", 0, ""},           // plain page
	}
	for _, c := range cases {
		got := classifyEndpoint(c.method, c.path)
		if got.tier != c.tier || got.class != c.class {
			t.Errorf("%s %s -> (tier %d, %q), want (tier %d, %q)", c.method, c.path, got.tier, got.class, c.tier, c.class)
		}
	}
}
