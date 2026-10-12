package gored_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	gored "github.com/t0ul/GORED"
)

// TestCanarySeederPlantsAndReachable seeds the demo target with no model (the
// deterministic minimal-body path, grounded on a GET sample of the collection) as
// the privileged admin, then confirms the planted marker is reachable: it shows up
// in the unscoped list a low-privilege identity can read (the broken access control),
// and NOT in the scoped list — so the canary gives ground truth a differential guess
// cannot. Real HTTP, no mocks.
func TestCanarySeederPlantsAndReachable(t *testing.T) {
	_, base := liveTarget(t)
	seeder := &gored.CanarySeeder{
		Base: base, Egress: gored.NewEgress(authority(t, base)), Sessions: gored.NewSessions(),
		Priv: gored.Identity{Name: "admin", Headers: map[string]string{"X-Session": "admin-session"}},
	}
	canaries, err := seeder.Seed(context.Background(), []string{
		"/api/memos",      // creatable: a POST handler exists
		"/api/memos/mine", // no POST handler -> refused, skipped
		"/api/notes",      // no POST handler -> refused, skipped
		"/api/auth/login", // not a create candidate -> never attempted
	})
	if err != nil {
		t.Fatal(err)
	}
	planted := gored.PlantedMarkers(canaries)
	if len(planted) != 1 {
		t.Fatalf("want exactly one planted canary (/api/memos), got %d: %+v", len(planted), canaries)
	}
	marker := planted[0]

	// The marker lands in the unscoped list a low-priv identity (alice) can read.
	if body := getAs(t, base, "/api/memos", "alice-session"); !strings.Contains(body, marker) {
		t.Errorf("planted marker not reachable via the unscoped list as low-priv: %s", body)
	}
	// It must NOT appear in the correctly scoped list (alice sees only her own).
	if body := getAs(t, base, "/api/memos/mine", "alice-session"); strings.Contains(body, marker) {
		t.Errorf("scoped list leaked the admin-owned canary: %s", body)
	}
}

func getAs(t *testing.T, base, path, session string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	req.Header.Set("X-Session", session)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
