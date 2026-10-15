package probes

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/t0ul/GORED/demotarget"
)

// Real system, no model: the vulnerable demotarget leaves GraphQL introspection enabled, so the
// probe POSTs the introspection query and parses the real schema the server discloses. The surface
// it recovers — including the id-taking note(id) operation flagged as an IDOR/BAC candidate — is the
// ingestion the tool exists to produce.
func TestGraphQLIntrospectLive(t *testing.T) {
	base, done := startDemotarget(t)
	defer done()
	out, err := GraphQLIntrospectTool{Gate: demoGate(t, base), Base: base}.Call(context.Background(), map[string]any{
		"path": "/graphql",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"note", "createNote", "IDOR/BAC candidate"} {
		if !strings.Contains(out, want) {
			t.Fatalf("introspection should recover the schema surface (missing %q); got: %s", want, out)
		}
	}
}

// The hardened build disables introspection, so the schema is never disclosed and the probe recovers
// no surface — a properly configured endpoint yields no attackable ingestion and no false surface.
func TestGraphQLIntrospectHardenedDisabled(t *testing.T) {
	srv, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()
	base := "http://" + ln.Addr().String()
	out, err := GraphQLIntrospectTool{Gate: demoGate(t, base), Base: base}.Call(context.Background(), map[string]any{"path": "/graphql"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "IDOR/BAC candidate") || strings.Contains(out, "graphql surface:") {
		t.Fatalf("hardened build must not disclose a GraphQL surface (introspection disabled); got: %s", out)
	}
}
