package probes

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/ingest"
	"github.com/t0ul/GORED/internal/tools"
)

// GraphQL ingestion: GORED reads OpenAPI/REST but is blind to a GraphQL endpoint, which is one POST
// /graphql with a query body rather than a set of routes. Introspection is GraphQL's self-describing
// schema — enabling it (the default in many frameworks) hands an attacker the full operation list.
// This probe introspects the endpoint and turns its schema into named attack surface the agent can
// drive via api_request: every id-taking query/mutation is a GraphQL IDOR/BAC candidate, the direct
// analog of a REST {id} template. It is generic (a standard introspection query, no app-specific
// names) and contained (a single POST through the Egress gate).

// GraphQLIntrospectProbe POSTs the introspection query to a GraphQL endpoint and parses the schema.
type GraphQLIntrospectProbe struct {
	Base    string
	Egress  *core.Egress
	Path    string // default /graphql
	Timeout time.Duration
}

// Introspect sends the introspection query and returns the parsed surface. An endpoint with
// introspection disabled returns an error (no __schema), which surfaces as a parse error, not a
// false surface.
func (p *GraphQLIntrospectProbe) Introspect(ctx context.Context) (ingest.GraphQLSurface, error) {
	path := p.Path
	if path == "" {
		path = "/graphql"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	raw := p.Base + path
	if p.Egress == nil || !p.Egress.Allowed(raw) {
		return ingest.GraphQLSurface{}, fmt.Errorf("%w: %s", core.ErrEgressDenied, raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, bytes.NewReader([]byte(ingest.IntrospectionQuery)))
	if err != nil {
		return ingest.GraphQLSurface{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	to := p.Timeout
	if to == 0 {
		to = 10 * time.Second
	}
	client := &http.Client{Timeout: to, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return ingest.GraphQLSurface{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return ingest.ParseIntrospection(body)
}

// GraphQLIntrospectTool (graphql_introspect) exposes schema introspection to the agent loop. It is
// ingestion, not a capture: it returns the attackable GraphQL surface (the agent exploits it with
// api_request), and highlights the id-taking operations as IDOR/BAC candidates.
type GraphQLIntrospectTool struct {
	Gate *tools.Gate
	Base string
}

func (GraphQLIntrospectTool) Name() string { return "graphql_introspect" }
func (GraphQLIntrospectTool) Describe() string {
	return `Introspect a GraphQL endpoint and list its attackable surface (queries, mutations, and the ` +
		`id-taking operations that are IDOR/BAC candidates). args: {"path":"/graphql"}. ` +
		`Exploit a candidate with api_request: POST the path with a crafted query body for another identity's id.`
}

func (t GraphQLIntrospectTool) Call(ctx context.Context, args map[string]any) (string, error) {
	p := &GraphQLIntrospectProbe{
		Base:   t.Base,
		Egress: t.Gate.Egress(),
		Path:   tools.AsString(args["path"]),
	}
	s, err := p.Introspect(ctx)
	if err != nil {
		return fmt.Sprintf("graphql: introspection unavailable (%v) — endpoint may disable introspection or not be GraphQL", err), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "graphql surface: %d operation(s) (query=%s mutation=%s)\n", len(s.Ops), s.QueryType, s.MutationType)
	for _, o := range s.Ops {
		var as []string
		for _, a := range o.Args {
			as = append(as, a.Name+":"+a.Type)
		}
		mark := ""
		if o.HasIDArg {
			mark = "  <- IDOR/BAC candidate (id arg)"
		}
		fmt.Fprintf(&b, "- %s %s(%s): %s%s\n", o.Kind, o.Name, strings.Join(as, ", "), o.Returns, mark)
	}
	if ids := s.IDOps(); len(ids) > 0 {
		var names []string
		for _, o := range ids {
			names = append(names, o.Name)
		}
		fmt.Fprintf(&b, "candidates: %s\n", strings.Join(names, ", "))
	}
	return b.String(), nil
}
