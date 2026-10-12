package gored_test

import (
	"os"
	"path/filepath"
	"testing"

	gored "github.com/t0ul/GORED"
)

func boolPtr(b bool) *bool { return &b }

// TestGoAnalyzerRungs builds a real Go module tree and checks each finding lands on the
// right static rung: a dependency in go.mod that a Go scanner marked unreachable is
// ruled out, a reachable one is reachable, a dependency not in go.mod is absent, a
// SAST file that exists is present, a missing one is absent, and a DAST URL is unknown.
func TestGoAnalyzerRungs(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/app\n\ngo 1.27\n\nrequire golang.org/x/crypto v0.1.0\n"), 0o644))
	must(os.MkdirAll(filepath.Join(dir, "pkg", "auth"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "pkg", "auth", "handlers.go"), []byte("package auth\n"), 0o644))

	a := gored.DetectAnalyzer(dir)
	if a == nil || a.Lang() != "go" {
		t.Fatalf("DetectAnalyzer should find go, got %v", a)
	}
	if gored.DetectAnalyzer(t.TempDir()) != nil {
		t.Errorf("a dir with no go.mod should yield no analyzer")
	}

	cases := []struct {
		name string
		f    gored.ScannerFinding
		want gored.Rung
	}{
		{"dep present, unreachable", gored.ScannerFinding{Location: "golang.org/x/crypto", Reachable: boolPtr(false)}, gored.RungRuledOut},
		{"dep present, reachable", gored.ScannerFinding{Location: "golang.org/x/crypto/openpgp", Reachable: boolPtr(true)}, gored.RungReachable},
		{"dep absent", gored.ScannerFinding{Location: "github.com/evil/pkg", Reachable: boolPtr(true)}, gored.RungAbsent},
		{"stdlib reachable", gored.ScannerFinding{Location: "stdlib", Reachable: boolPtr(true)}, gored.RungReachable},
		{"sast file exists", gored.ScannerFinding{Location: "pkg/auth/handlers.go:12"}, gored.RungPresent},
		{"sast file missing", gored.ScannerFinding{Location: "pkg/nope/x.go:1"}, gored.RungAbsent},
		{"dast url", gored.ScannerFinding{Location: "/login"}, gored.RungUnknown},
	}
	for _, c := range cases {
		got, why := a.Analyze(c.f)
		if got != c.want {
			t.Errorf("%s: want %q, got %q (%s)", c.name, c.want, got, why)
		}
	}
}
