package eva

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/t0ul/GORED/store"
)

// reconTool lets the exploit-phase model PULL a scoped slice of the target's reconned surface from
// project memory — the not-yet-exercised frontier with each endpoint's reverse-engineered contract
// (typed fields, required flags, query/path params, headers, per-identity auth) — instead of having
// the whole map dumped into its prompt. It returns a dense, one-line-per-endpoint listing the model
// can act on directly (build a schema-valid request, pick a reachable identity, see what's been tried).
type reconTool struct {
	store      *store.Store
	target     string
	attemptCap int // attempts ceiling below which an endpoint still counts as frontier
}

func (reconTool) Name() string { return "recon" }

func (reconTool) Describe() string {
	return `List the target's reconned endpoints and their request contracts from project memory, scoped so you pull only what you need. ` +
		`args: {"exercised": false, "class": "", "limit": 20}. ` +
		`Default returns the not-yet-exercised frontier (endpoints with no finding and few attempts); set "exercised": true to include worked ones. ` +
		`Optional "class" filters to one attack class (auth, write, upload, ingest, export, search, info, ssrf, idor, admin). ` +
		`Each line is: METHOD /path (class) | body/query/path fields as name:type (! = required) | hdr: required headers | auth: identity=status | tried:N. Use the fields to build a schema-valid request and auth to pick a reachable identity.`
}

func (t reconTool) Call(ctx context.Context, args map[string]any) (string, error) {
	if t.store == nil || t.target == "" {
		return "", fmt.Errorf("recon: no project store bound to this run")
	}
	rows, err := t.store.QueryEndpoints(t.target, store.QueryOpts{
		Exercised:  argBool(args["exercised"]),
		AttemptCap: t.attemptCap,
		Class:      strings.TrimSpace(asStr(args["class"])),
		Limit:      argInt(args["limit"]),
	})
	if err != nil {
		return "", fmt.Errorf("recon: %w", err)
	}
	if len(rows) == 0 {
		return "no endpoints match: the target may not be reconned yet, or the whole frontier is exercised (try {\"exercised\": true} or a different class).", nil
	}
	// Rank easiest-first by attack difficulty (the store can't: difficulty is an eva concept). Stable,
	// so QueryEndpoints' secondary order (fewest attempts) is preserved within a difficulty tier.
	sort.SliceStable(rows, func(i, j int) bool {
		return classifyEndpoint(rows[i].Method, rows[i].Path).difficulty < classifyEndpoint(rows[j].Method, rows[j].Path).difficulty
	})
	var b strings.Builder
	scope := "frontier (not yet exercised)"
	if argBool(args["exercised"]) {
		scope = "all"
	}
	fmt.Fprintf(&b, "# %s endpoints on %s — legend: field:type  ! = required  | auth identity=status | tried:N\n", scope, t.target)
	for _, r := range rows {
		b.WriteString(formatEndpointLine(r))
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// formatEndpointLine renders one endpoint as a dense, directly-actionable line for the model.
func formatEndpointLine(r store.SurfaceRow) string {
	var sb strings.Builder
	class := r.Class
	if class == "" {
		class = "-"
	}
	fmt.Fprintf(&sb, "%-6s %s (%s)", r.Method, r.Path, class)
	if r.Contract != nil {
		body, query, path := splitFieldsByIn(r.Contract.Fields)
		if s := fieldList(body); s != "" {
			sb.WriteString("  body: " + s)
		}
		if s := fieldList(query); s != "" {
			sb.WriteString("  query: " + s)
		}
		if s := fieldList(path); s != "" {
			sb.WriteString("  path: " + s)
		}
		if len(r.Contract.Headers) > 0 {
			sb.WriteString("  hdr: " + strings.Join(r.Contract.Headers, " "))
		}
		if a := authList(r.Contract.Auth); a != "" {
			sb.WriteString("  auth: " + a)
		}
	}
	fmt.Fprintf(&sb, "  tried:%d", r.Attempts)
	if r.Captured {
		sb.WriteString(" [found]")
	}
	return sb.String()
}

func splitFieldsByIn(fs []store.FieldSpec) (body, query, path []store.FieldSpec) {
	for _, f := range fs {
		switch f.In {
		case "query":
			query = append(query, f)
		case "path":
			path = append(path, f)
		default:
			body = append(body, f)
		}
	}
	return
}

func fieldList(fs []store.FieldSpec) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		s := f.Name
		if f.Type != "" && f.Type != "unknown" {
			s += ":" + f.Type
		}
		if f.Required {
			s += "!"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// authList renders the per-identity status map in a stable order (anon, low, priv, then any others).
func authList(a map[string]int) string {
	if len(a) == 0 {
		return ""
	}
	order := []string{"anon", "low", "priv"}
	seen := map[string]bool{}
	var parts []string
	for _, id := range order {
		if st, ok := a[id]; ok {
			parts = append(parts, fmt.Sprintf("%s=%d", id, st))
			seen[id] = true
		}
	}
	var extra []string
	for id := range a {
		if !seen[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	for _, id := range extra {
		parts = append(parts, fmt.Sprintf("%s=%d", id, a[id]))
	}
	return strings.Join(parts, " ")
}

// argBool / argInt coerce a tool argument that may arrive as a native bool/number or a string.
func argBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		b, _ := strconv.ParseBool(strings.TrimSpace(t))
		return b
	}
	return false
}

func argInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	}
	return 0
}
