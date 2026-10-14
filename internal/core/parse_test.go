package core

import "testing"

func TestExtractJSONBalances(t *testing.T) {
	cases := map[string]string{
		`{"tool":"http_request"}`:                          `{"tool":"http_request"}`,
		"blah {\"a\":{\"b\":1}} trailing":                  `{"a":{"b":1}}`,
		`prefix {"s":"has } brace in string"} end`:         `{"s":"has } brace in string"}`,
		"x {\"s\":\"escaped \\\" quote\",\"done\":true} y": `{"s":"escaped \" quote","done":true}`,
	}
	for in, want := range cases {
		got, ok := ExtractJSON(in)
		if !ok || got != want {
			t.Errorf("ExtractJSON(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	if _, ok := ExtractJSON("no json here"); ok {
		t.Error("expected no JSON")
	}
}

func TestParseAction(t *testing.T) {
	a, ok := parseAction(`I will fetch. {"tool":"http_request","args":{"path":"/api/notes/1000"}}`)
	if !ok || a.Tool != "http_request" || a.Args["path"] != "/api/notes/1000" {
		t.Fatalf("tool call parse wrong: %+v ok=%v", a, ok)
	}
	d, ok := parseAction(`{"done":true,"flag":"GORED{x}"}`)
	if !ok || !d.Done || d.Flag != "GORED{x}" {
		t.Fatalf("done parse wrong: %+v ok=%v", d, ok)
	}
	if _, ok := parseAction("just prose, no object"); ok {
		t.Fatal("prose should not parse")
	}
	if _, ok := parseAction(`{"thought":"hmm"}`); ok {
		t.Fatal("object with neither tool nor done should not parse as an action")
	}
}

func TestExtractFlagMarker(t *testing.T) {
	if got := extractFlagMarker("HTTP 200\nbody GORED{abc123} tail"); got != "GORED{abc123}" {
		t.Fatalf("got %q", got)
	}
	if got := extractFlagMarker("no marker here"); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
	if got := extractFlagMarker("GORED{unterminated"); got != "" {
		t.Fatalf("unterminated marker should yield empty, got %q", got)
	}
}
