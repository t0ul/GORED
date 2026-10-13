package gored

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// ModelSpec is one swappable model the benchmark can name in a config. A model is either
// reached at an existing OpenAI-compatible Endpoint (DeepSeek, Kimi/Moonshot, a local
// vLLM/Ollama, anything), or served locally from a GGUF by goserve. Making this a named,
// serializable spec is what lets a run swap "qwen3b" for "deepseek" by changing one string,
// and lets the leaderboard key a result by exactly which models filled which roles.
type ModelSpec struct {
	Name     string  `json:"name"`               // logical name used in configs + the leaderboard
	Endpoint string  `json:"endpoint,omitempty"` // OpenAI-compatible chat URL; empty => served locally from a GGUF
	Model    string  `json:"model,omitempty"`    // model id the endpoint expects; defaults to Name
	GGUF     string  `json:"gguf,omitempty"`     // local GGUF filename (served via goserve) when Endpoint is empty
	Port     int     `json:"port,omitempty"`     // local serve port
	Ctx      int     `json:"ctx,omitempty"`      // context window for the local serve
	ParamsB  float64 `json:"params_b,omitempty"` // declared size in billions, for the iso-budget footprint
}

// Local reports whether the spec is served locally from a GGUF rather than an endpoint.
func (s ModelSpec) Local() bool { return s.Endpoint == "" }

// ModelID is the id to send to the endpoint: Model, or Name when Model is unset.
func (s ModelSpec) ModelID() string {
	if s.Model != "" {
		return s.Model
	}
	return s.Name
}

// ModelRegistry resolves a logical model name to its spec. It holds no clients and boots
// nothing itself — it is the swappable catalog the harness reads; the caller builds a
// client (modelclient.FromSpec) or boots a local model (goserve) from the resolved spec.
// This keeps the registry pure (no cgo, no network) and the model fully swappable.
type ModelRegistry struct{ byName map[string]ModelSpec }

// NewModelRegistry indexes specs by name. A later spec with a repeated name wins.
func NewModelRegistry(specs []ModelSpec) *ModelRegistry {
	m := &ModelRegistry{byName: make(map[string]ModelSpec, len(specs))}
	for _, s := range specs {
		m.byName[s.Name] = s
	}
	return m
}

// LoadRegistry reads a JSON array of ModelSpec from a file, so the model catalog is data,
// not code — swap models by editing the file, not the binary.
func LoadRegistry(path string) (*ModelRegistry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var specs []ModelSpec
	if err := json.Unmarshal(b, &specs); err != nil {
		return nil, fmt.Errorf("model registry %s: %w", path, err)
	}
	return NewModelRegistry(specs), nil
}

// Resolve returns the spec for a name, or an error naming the miss.
func (r *ModelRegistry) Resolve(name string) (ModelSpec, error) {
	s, ok := r.byName[name]
	if !ok {
		return ModelSpec{}, fmt.Errorf("model %q not in registry", name)
	}
	return s, nil
}

// Names lists the registered model names, sorted.
func (r *ModelRegistry) Names() []string {
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ComputeAccount is the per-model resource record a run accrues, so configs compare at
// iso-budget rather than on raw score: tokens, wall time, call count, and the model's
// declared footprint. The leaderboard keys results by {shape, models, budget}; this is the
// budget.
type ComputeAccount struct {
	Model     string  `json:"model"`
	Backend   string  `json:"backend"` // "local" | "remote"
	Calls     int     `json:"calls"`
	TokensIn  int     `json:"tokens_in"`
	TokensOut int     `json:"tokens_out"`
	WallMS    int64   `json:"wall_ms"`
	ParamsB   float64 `json:"params_b,omitempty"`
}

// NewComputeAccount starts an account for a model, tagging its backend and footprint.
func NewComputeAccount(s ModelSpec) *ComputeAccount {
	backend := "remote"
	if s.Local() {
		backend = "local"
	}
	return &ComputeAccount{Model: s.Name, Backend: backend, ParamsB: s.ParamsB}
}

func (a *ComputeAccount) record(u Usage, wall time.Duration) {
	a.Calls++
	a.TokensIn += u.PromptTokens
	a.TokensOut += u.CompletionTokens
	a.WallMS += wall.Milliseconds()
}

// AccountingClient wraps any ModelClient and records every call into a ComputeAccount, so
// compute accounting rides along with any run without the objective loop knowing about it.
// It is a drop-in ModelClient, so an experiment wraps its models once and reads the budget
// off the account afterward.
type AccountingClient struct {
	inner   ModelClient
	Account *ComputeAccount
}

// NewAccountingClient wraps inner so its calls accrue into acct.
func NewAccountingClient(inner ModelClient, acct *ComputeAccount) *AccountingClient {
	return &AccountingClient{inner: inner, Account: acct}
}

func (c *AccountingClient) Name() string { return c.inner.Name() }

func (c *AccountingClient) Chat(ctx context.Context, msgs []Message, opts ChatOpts) (string, Usage, error) {
	start := time.Now()
	reply, usage, err := c.inner.Chat(ctx, msgs, opts)
	c.Account.record(usage, time.Since(start))
	return reply, usage, err
}
