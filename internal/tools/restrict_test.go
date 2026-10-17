package tools

import (
	"context"
	"testing"
)

type stubTool struct{ name string }

func (s stubTool) Name() string                                       { return s.name }
func (s stubTool) Describe() string                                   { return s.name }
func (stubTool) Call(context.Context, map[string]any) (string, error) { return "", nil }

// Restrict scopes a toolbox to exactly the named tools (order preserved), the mechanism that
// phase-scopes a focused exploit run to one endpoint class's tools.
func TestToolboxRestrict(t *testing.T) {
	mk := func() *Toolbox {
		return NewToolbox(stubTool{"http_request"}, stubTool{"discover"}, stubTool{"mass_assign"}, stubTool{"body_limit"})
	}

	// keep a subset, in the toolbox's own order
	tb := mk()
	tb.Restrict([]string{"body_limit", "mass_assign"})
	if got := tb.Names(); len(got) != 2 || got[0] != "mass_assign" || got[1] != "body_limit" {
		t.Fatalf("restrict should keep only the named tools in order; got %v", got)
	}
	if _, ok := tb.Get("discover"); ok {
		t.Errorf("discover should have been dropped")
	}

	// empty names is a no-op (unscoped run keeps everything)
	tb = mk()
	tb.Restrict(nil)
	if len(tb.Names()) != 4 {
		t.Errorf("empty restrict must be a no-op; got %v", tb.Names())
	}

	// names that match nothing leave the toolbox intact (never strand the model with zero tools)
	tb = mk()
	tb.Restrict([]string{"no_such_tool"})
	if len(tb.Names()) != 4 {
		t.Errorf("an all-unknown restrict must leave the toolbox intact; got %v", tb.Names())
	}

	// a mix keeps only the known ones
	tb = mk()
	tb.Restrict([]string{"mass_assign", "no_such_tool"})
	if got := tb.Names(); len(got) != 1 || got[0] != "mass_assign" {
		t.Fatalf("restrict should keep the known tool and ignore the unknown; got %v", got)
	}
}
