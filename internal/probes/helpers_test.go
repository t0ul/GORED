package probes_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/t0ul/GORED/demotarget"
)

// liveTarget / authority mirror the root package's test helpers (tool_test.go). The probe
// tests run against a live demotarget server, so they carry their own copies here rather than
// reach across the package boundary into the root tests.

func liveTarget(t *testing.T) (*demotarget.Server, string) {
	t.Helper()
	s, err := demotarget.New()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts.URL
}

func authority(_ *testing.T, base string) string {
	return strings.TrimPrefix(base, "http://")
}
