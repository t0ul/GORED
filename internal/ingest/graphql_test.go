package ingest

import "testing"

// Pure logic: parse a representative introspection response and assert the surface, type unwrapping
// (NON_NULL/LIST -> named type), and id-arg detection (by arg name and by ID type).
func TestParseIntrospection(t *testing.T) {
	resp := []byte(`{"data":{"__schema":{
		"queryType":{"name":"Query","fields":[
			{"name":"note","args":[{"name":"id","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"ID"}}}],"type":{"kind":"OBJECT","name":"Note"}},
			{"name":"notes","args":[],"type":{"kind":"LIST","name":null,"ofType":{"kind":"OBJECT","name":"Note"}}},
			{"name":"userByToken","args":[{"name":"token","type":{"kind":"SCALAR","name":"ID"}}],"type":{"kind":"OBJECT","name":"User"}},
			{"name":"__type","args":[],"type":{"kind":"OBJECT","name":"__Type"}}
		]},
		"mutationType":{"name":"Mutation","fields":[
			{"name":"createNote","args":[{"name":"title","type":{"kind":"SCALAR","name":"String"}}],"type":{"kind":"OBJECT","name":"Note"}}
		]}
	}}}`)
	s, err := ParseIntrospection(resp)
	if err != nil {
		t.Fatal(err)
	}
	if s.QueryType != "Query" || s.MutationType != "Mutation" {
		t.Fatalf("root types: query=%q mutation=%q", s.QueryType, s.MutationType)
	}
	// __type is a meta-field and must be skipped; the rest are ops (sorted by name).
	byName := map[string]GraphQLOp{}
	for _, o := range s.Ops {
		if o.Name == "__type" {
			t.Fatalf("introspection meta-field __type should be skipped")
		}
		byName[o.Name] = o
	}
	if len(byName) != 4 {
		t.Fatalf("want 4 ops, got %d: %+v", len(byName), s.Ops)
	}
	// note: NON_NULL(ID) arg named id -> HasIDArg, return type unwrapped to Note.
	if n := byName["note"]; !n.HasIDArg || n.Returns != "Note" || n.Args[0].Type != "ID" {
		t.Fatalf("note op parsed wrong: %+v", n)
	}
	// userByToken: no arg named id, but the arg's type is ID -> still an id-taking candidate.
	if !byName["userByToken"].HasIDArg {
		t.Fatalf("an ID-typed arg should mark the op as an id-taking candidate: %+v", byName["userByToken"])
	}
	// notes: LIST(Note) return unwrapped to Note, no id arg.
	if n := byName["notes"]; n.HasIDArg || n.Returns != "Note" {
		t.Fatalf("notes op parsed wrong: %+v", n)
	}
	// createNote: a mutation, no id arg.
	if m := byName["createNote"]; m.Kind != "mutation" || m.HasIDArg {
		t.Fatalf("createNote op parsed wrong: %+v", m)
	}
	ids := s.IDOps()
	if len(ids) != 2 {
		t.Fatalf("want 2 id-taking candidates (note, userByToken), got %d: %+v", len(ids), ids)
	}
}

// Disabled introspection (the hardened posture) returns errors and no __schema, which must be a
// parse error, not an empty-but-successful surface.
func TestParseIntrospectionDisabled(t *testing.T) {
	if _, err := ParseIntrospection([]byte(`{"errors":[{"message":"GraphQL introspection is disabled"}]}`)); err == nil {
		t.Fatal("disabled introspection should return an error, not an empty surface")
	}
}
