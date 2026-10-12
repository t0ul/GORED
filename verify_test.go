package gored

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParsePlan(t *testing.T) {
	p, ok := parsePlan(`sure: {"steps":[{"method":"POST","path":"/login","body":"x"},{"method":"GET","path":"/secret"}]}`)
	if !ok || len(p.Steps) != 2 || p.Steps[1].Path != "/secret" {
		t.Fatalf("parse wrong: %+v ok=%v", p, ok)
	}
	if _, ok := parsePlan("no json"); ok {
		t.Fatal("prose should not parse")
	}
}

// A real server where /secret discloses the marker only to a logged-in session.
func markerServer(t *testing.T, marker string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err != nil || c.Value != "ok" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
			return
		}
		_, _ = w.Write([]byte("here is the " + marker))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestVerifierRunReproduces(t *testing.T) {
	const marker = "GORED{deadbeef}"
	ts := markerServer(t, marker)
	v := Verifier{Base: ts.URL, Marker: marker}

	// The right plan — log in, then read the secret — reproduces.
	good := ReproPlan{Steps: []ReproStep{
		{Method: "POST", Path: "/login"},
		{Method: "GET", Path: "/secret"},
	}}
	if leaked, _ := v.run(context.Background(), good); !leaked {
		t.Fatal("a correct plan did not reproduce the disclosure")
	}

	// The wrong plan — skip login — must NOT reproduce. Execution is the gate.
	bad := ReproPlan{Steps: []ReproStep{{Method: "GET", Path: "/secret"}}}
	if leaked, _ := v.run(context.Background(), bad); leaked {
		t.Fatal("an unauthenticated plan should not have disclosed the marker")
	}
}

func TestRenderCurlShape(t *testing.T) {
	v := Verifier{Base: "http://x:1", Marker: "GORED{z}"}
	s := v.renderCurl(ReproPlan{Steps: []ReproStep{
		{Method: "POST", Path: "/login", Body: "{}"},
		{Method: "GET", Path: "/secret"},
	}})
	if !strings.Contains(s, "curl -s -c") || !strings.Contains(s, "/secret") || !strings.Contains(s, "grep -q 'GORED{'") {
		t.Fatalf("curl render missing expected parts:\n%s", s)
	}
}
