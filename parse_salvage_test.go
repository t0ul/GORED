package gored

import "testing"

func TestStripThink(t *testing.T) {
	cases := map[string]string{
		`<think>let me reason</think>{"tool":"x"}`: `{"tool":"x"}`,
		`a<think>one</think>b<think>two</think>c`:  `abc`,
		`{"tool":"x"}`: `{"tool":"x"}`,
		`<think>unclosed reasoning that got cut off`: ``,
	}
	for in, want := range cases {
		if got := stripThink(in); got != want {
			t.Errorf("stripThink(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseActionsRescuesReasoningModel(t *testing.T) {
	// A reasoning model wraps its real tool call in a think block.
	reply := `<think>The app has /api/notes. I should try id 1000 as the admin note.</think>
{"tool":"http_request","args":{"method":"GET","path":"/api/notes/1000"}}`
	acts := parseActions(reply)
	if len(acts) != 1 || acts[0].Tool != "http_request" || acts[0].Args["path"] != "/api/notes/1000" {
		t.Fatalf("reasoning tool call not parsed: %+v", acts)
	}
}

func TestParseActionsSalvagesStrayQuote(t *testing.T) {
	// The exact Mistral-family malformation observed live: a stray quote before the
	// final brace breaks strict extraction; the salvage must still recover the call.
	reply := `{"tool":"http_request","args":{"method":"GET","path":"/api/notes/1","headers":{"X-Session":"alice-session"}}"}`
	if acts := parseActions(reply); len(acts) == 0 {
		t.Fatal("strict+salvage parse found no action in a near-miss reply")
	} else if acts[0].Tool != "http_request" || acts[0].Args["path"] != "/api/notes/1" {
		t.Errorf("salvaged the wrong call: %+v", acts[0])
	}
}

func TestRepairLeavesGoodJSONUntouched(t *testing.T) {
	good := `{"tool":"http_request","args":{"path":"/x"}}`
	if repairNearJSON(good) != good {
		t.Errorf("repair altered well-formed JSON: %q", repairNearJSON(good))
	}
}

func TestMaxOutTokensDefault(t *testing.T) {
	if (Bounds{}).withDefaults().MaxOutTokens != 256 {
		t.Error("default MaxOutTokens should be 256")
	}
	if (Bounds{MaxOutTokens: 2048}).withDefaults().MaxOutTokens != 2048 {
		t.Error("explicit MaxOutTokens must be preserved")
	}
}
