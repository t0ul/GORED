package gored_test

import (
	"testing"

	gored "github.com/t0ul/GORED"
)

// TestModelRegistry covers the swappable catalog: resolve by name, error on a miss, sorted
// names, and the local-vs-remote / model-id logic a config depends on.
func TestModelRegistry(t *testing.T) {
	specs := []gored.ModelSpec{
		{Name: "qwen3b", GGUF: "qwen2.5-3b-instruct.gguf", Port: 11630, Ctx: 4096, ParamsB: 3},
		{Name: "deepseek", Endpoint: "http://127.0.0.1:8001/v1/chat/completions", Model: "deepseek-coder", ParamsB: 16},
	}
	r := gored.NewModelRegistry(specs)

	if got := r.Names(); len(got) != 2 || got[0] != "deepseek" || got[1] != "qwen3b" {
		t.Fatalf("Names should be sorted, got %v", got)
	}
	if _, err := r.Resolve("nope"); err == nil {
		t.Error("Resolve of an unknown model should error")
	}

	q, err := r.Resolve("qwen3b")
	if err != nil {
		t.Fatal(err)
	}
	if !q.Local() {
		t.Error("a GGUF spec with no endpoint should be local")
	}
	if q.ModelID() != "qwen3b" {
		t.Errorf("ModelID should fall back to Name, got %q", q.ModelID())
	}

	d, _ := r.Resolve("deepseek")
	if d.Local() {
		t.Error("a spec with an endpoint should be remote")
	}
	if d.ModelID() != "deepseek-coder" {
		t.Errorf("ModelID should use Model when set, got %q", d.ModelID())
	}
}

// TestComputeAccountBackend checks the footprint record tags the right backend from the spec.
func TestComputeAccountBackend(t *testing.T) {
	local := gored.NewComputeAccount(gored.ModelSpec{Name: "qwen3b", GGUF: "q.gguf", ParamsB: 3})
	if local.Backend != "local" || local.ParamsB != 3 {
		t.Errorf("local account wrong: %+v", local)
	}
	remote := gored.NewComputeAccount(gored.ModelSpec{Name: "kimi", Endpoint: "http://x/v1/chat/completions"})
	if remote.Backend != "remote" {
		t.Errorf("remote account wrong: %+v", remote)
	}
}
