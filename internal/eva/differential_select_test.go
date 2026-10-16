package eva

import (
	"testing"

	"github.com/t0ul/GORED/store"
)

// differentialTargets must pick only the crown-jewel reads (IDOR/admin), force every one to GET
// (the probe is read-only), dedupe by path, skip synthetic surface rows, and bound the count.
func TestDifferentialTargets(t *testing.T) {
	rows := []store.SurfaceRow{
		{Method: "GET", Path: "/api/tickets/{id}"},        // idor -> selected
		{Method: "GET", Path: "/api/tickets/{id}"},        // same path again -> deduped
		{Method: "GET", Path: "/admin"},                   // admin -> selected
		{Method: "POST", Path: "/krab/login"},             // auth (tier 1) -> NOT a differential class
		{Method: "GET", Path: "/api/config"},              // info (tier 3) -> skipped
		{Method: "POST", Path: "/api/images/upload"},      // upload (tier 2) -> skipped
		{Method: "GET", Path: "/about"},                   // plain page (tier 0) -> skipped
		{Method: "POST", Path: "/graphql query listUsers"}, // synthetic (has a space) -> skipped
	}
	mps := differentialTargets(rows)

	if len(mps) != 2 {
		t.Fatalf("expected 2 crown-jewel reads, got %d: %v", len(mps), mps)
	}
	for _, mp := range mps {
		if mp[0] != "GET" {
			t.Errorf("probe must be read-only (GET), got %q for %q", mp[0], mp[1])
		}
	}
	paths := map[string]bool{mps[0][1]: true, mps[1][1]: true}
	if !paths["/api/tickets/{id}"] || !paths["/admin"] {
		t.Errorf("wrong selection: %v", mps)
	}
}

// differentialTargets must cap the sweep so a huge mapped surface stays bounded.
func TestDifferentialTargetsCap(t *testing.T) {
	var rows []store.SurfaceRow
	for i := 0; i < differentialCap+25; i++ {
		rows = append(rows, store.SurfaceRow{Method: "GET", Path: "/api/resource" + itoa(i) + "/1"})
	}
	if got := len(differentialTargets(rows)); got != differentialCap {
		t.Fatalf("expected cap %d, got %d", differentialCap, got)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
