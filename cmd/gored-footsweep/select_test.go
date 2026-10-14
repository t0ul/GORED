package main

import "testing"

// TestSelectTechnique pins the living-off-the-land selection: pick the first technique the
// box's discovered capabilities support, native before the delivered Go fallback, and nothing
// hardcoded to a stack. Pure logic, no network.
func TestSelectTechnique(t *testing.T) {
	cases := []struct {
		name    string
		caps    map[string]bool
		disable bool
		want    string
		none    bool
	}{
		{"busybox box (nc+mkfifo, has fallback)", caps("nc", "mkfifo", "go-revshell"), false, "nc-mkfifo", false},
		{"bash box prefers /dev/tcp", caps("bash", "nc", "mkfifo", "go-revshell"), false, "bash-dev-tcp", false},
		{"python box", caps("python3", "go-revshell"), false, "python3", false},
		{"bare box falls back to delivered Go", caps("go-revshell"), false, "go-revshell", false},
		{"truly nothing", caps(), false, "", true},
		{"force fallback even on a rich box", caps("bash", "nc", "mkfifo", "python3", "go-revshell"), true, "go-revshell", false},
		{"force fallback but no binary", caps("bash", "nc", "mkfifo"), true, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := selectTechnique(c.caps, c.disable)
			if c.none {
				if ok {
					t.Fatalf("expected no technique, got %q", got.name)
				}
				return
			}
			if !ok {
				t.Fatalf("expected %q, got none", c.want)
			}
			if got.name != c.want {
				t.Fatalf("selectTechnique = %q, want %q", got.name, c.want)
			}
		})
	}
}

func caps(toks ...string) map[string]bool {
	m := map[string]bool{}
	for _, t := range toks {
		m[t] = true
	}
	return m
}
