package gored

import (
	"context"
	"strings"
	"testing"
)

func TestParseLeads(t *testing.T) {
	// A small model wraps two lead objects in prose and skips a goalless one.
	reply := `Here is the plan:
{"goal":"probe /api/memos for IDOR by swapping the id","hint":"numeric id in path"}
some chatter
{"goal":"test the login for broken access control","hint":"/login"}
{"hint":"no goal here, drop me"}`
	leads := parseLeads(reply)
	if len(leads) != 2 {
		t.Fatalf("want 2 leads, got %d: %+v", len(leads), leads)
	}
	if leads[0].ID != 1 || leads[1].ID != 2 {
		t.Errorf("ids not sequential: %+v", leads)
	}
	if !strings.Contains(leads[0].Goal, "IDOR") || leads[1].Hint != "/login" {
		t.Errorf("fields mis-parsed: %+v", leads)
	}
}

func TestStaticPlanner(t *testing.T) {
	p := StaticPlanner{Leads: []Lead{{ID: 1, Goal: "a"}, {ID: 2, Goal: "b"}}, Label: "E"}
	got, err := p.Plan(context.Background(), Objective{}, NewBlackboard())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || p.Name() != "E" {
		t.Fatalf("plan=%+v name=%q", got, p.Name())
	}
	// Plan must return a copy, not the planner's own slice.
	got[0].Goal = "mutated"
	if p.Leads[0].Goal != "a" {
		t.Error("Plan leaked the backing slice")
	}
}

func TestEither(t *testing.T) {
	if either(true, "x", "y") != "x" || either(false, "x", "y") != "y" {
		t.Error("either wrong")
	}
}
