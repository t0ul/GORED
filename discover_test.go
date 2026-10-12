package gored_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gored "github.com/t0ul/GORED"
)

func TestDiscoverExtractsSameOriginSurface(t *testing.T) {
	const page = `<!doctype html><html><body>
<a href="/login">login</a>
<a href="/api/tickets">tickets</a>
<form action="/api/auth/login" method="post"><input name="email"></form>
<a href="https://evil.example/off-origin">off</a>
<a href="mailto:x@y.z">mail</a>
<script>
  fetch("/api/admin/users");
  const cfg = "/api/config";
</script>
</body></html>`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(page))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)

	d := gored.NewDiscoverTool(ts.URL, gored.NewEgress(authority(t, ts.URL)))
	out, err := d.Call(context.Background(), map[string]any{"path": "/"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/login", "/api/tickets", "/api/auth/login", "/api/admin/users", "/api/config"} {
		if !strings.Contains(out, want) {
			t.Errorf("discover missed %s\n%s", want, out)
		}
	}
	if strings.Contains(out, "evil.example") {
		t.Error("discover leaked an off-origin host")
	}
}
