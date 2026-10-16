package ingest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// GraphQL ingestion: an app that exposes a GraphQL endpoint is one POST with a query body, not a
// set of REST routes, so the OpenAPI ingest cannot see it. Introspection is the equivalent of a
// spec — it lists every query and mutation, their arguments, and return types. Ingesting it turns
// a GraphQL endpoint into named surface the agent can attack (an id-taking query is the GraphQL
// analog of a REST {id} template — the IDOR/BAC candidate the hunt looks for).

// IntrospectionQuery is a minimal schema introspection: the root query/mutation operations, their
// argument names/types, and return types — enough to enumerate the attackable surface.
const IntrospectionQuery = `{"query":"query{__schema{queryType{name fields{name args{name type{kind name ofType{kind name}}} type{kind name ofType{kind name}}} } mutationType{name fields{name args{name type{kind name ofType{kind name}}} type{kind name ofType{kind name}}}}}}"}`

// GraphQLArg is one argument of an operation.
type GraphQLArg struct {
	Name string
	Type string // the named type (unwrapping NON_NULL/LIST), e.g. "ID", "String"
}

// GraphQLOp is one root query or mutation: a named operation the client can call.
type GraphQLOp struct {
	Name     string
	Kind     string // "query" | "mutation"
	Args     []GraphQLArg
	Returns  string // named return type
	HasIDArg bool   // takes an argument named "id" or of type "ID" — an IDOR/BAC candidate
}

// GraphQLSurface is the introspected attack surface of a GraphQL endpoint.
type GraphQLSurface struct {
	QueryType    string
	MutationType string
	Ops          []GraphQLOp
}

// IDOps returns the operations that take an id-like argument — the IDOR/BAC candidates.
func (s GraphQLSurface) IDOps() []GraphQLOp {
	var out []GraphQLOp
	for _, o := range s.Ops {
		if o.HasIDArg {
			out = append(out, o)
		}
	}
	return out
}

// ParseIntrospection parses a GraphQL introspection response (the JSON returned for
// IntrospectionQuery) into the surface. It tolerates the standard {"data":{"__schema":...}} shape.
func ParseIntrospection(data []byte) (GraphQLSurface, error) {
	type gqlType struct {
		Kind   string   `json:"kind"`
		Name   string   `json:"name"`
		OfType *gqlType `json:"ofType"`
	}
	type gqlArg struct {
		Name string  `json:"name"`
		Type gqlType `json:"type"`
	}
	type gqlField struct {
		Name string   `json:"name"`
		Args []gqlArg `json:"args"`
		Type gqlType  `json:"type"`
	}
	type gqlRoot struct {
		Name   string     `json:"name"`
		Fields []gqlField `json:"fields"`
	}
	var resp struct {
		Data struct {
			Schema struct {
				QueryType    gqlRoot `json:"queryType"`
				MutationType gqlRoot `json:"mutationType"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return GraphQLSurface{}, fmt.Errorf("parse graphql introspection: %w", err)
	}
	sc := resp.Data.Schema
	if len(sc.QueryType.Fields) == 0 && len(sc.MutationType.Fields) == 0 {
		return GraphQLSurface{}, fmt.Errorf("graphql: no operations (introspection disabled or not a GraphQL endpoint?)")
	}
	named := func(t gqlType) string {
		for t.Name == "" && t.OfType != nil { // unwrap NON_NULL / LIST
			t = *t.OfType
		}
		return t.Name
	}
	s := GraphQLSurface{QueryType: sc.QueryType.Name, MutationType: sc.MutationType.Name}
	add := func(fields []gqlField, kind string) {
		for _, f := range fields {
			if strings.HasPrefix(f.Name, "__") {
				continue // introspection meta-fields
			}
			op := GraphQLOp{Name: f.Name, Kind: kind, Returns: named(f.Type)}
			for _, a := range f.Args {
				tn := named(a.Type)
				op.Args = append(op.Args, GraphQLArg{Name: a.Name, Type: tn})
				if strings.EqualFold(a.Name, "id") || strings.EqualFold(tn, "ID") {
					op.HasIDArg = true
				}
			}
			s.Ops = append(s.Ops, op)
		}
	}
	add(sc.QueryType.Fields, "query")
	add(sc.MutationType.Fields, "mutation")
	sort.Slice(s.Ops, func(i, j int) bool { return s.Ops[i].Name < s.Ops[j].Name })
	return s, nil
}
