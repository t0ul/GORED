package eva

import "testing"

// discoveredPaths must pull the crawl-found paths out of a discover result (and nothing out of an
// ordinary HTTP body), so the surface map reflects what discovery enumerated.
func TestDiscoveredPaths(t *testing.T) {
	res := "discovered 3 path(s):\n  /api/admin\n  /api/admin/users\n  /api/tickets/{id}"
	got := discoveredPaths(res)
	if len(got) != 3 || got[0] != "/api/admin" || got[2] != "/api/tickets/{id}" {
		t.Fatalf("discoveredPaths parsed wrong: %v", got)
	}
	// Not a discover result -> nothing, even though the body contains a path.
	if p := discoveredPaths(`HTTP 200 {"next":"/api/x"}`); len(p) != 0 {
		t.Fatalf("must not scrape paths from a non-discover body: %v", p)
	}
}
