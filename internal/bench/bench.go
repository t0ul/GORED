// Package bench is the shared sweep harness: the model-boot / registry / accounting /
// Sweep / output scaffolding that every GORED stage-sweep repeated in its main(). A sweep
// now supplies only what varies — the toolbox, skill, playbook, oracle and target (via a
// MakeRunner callback) plus a few labels — and bench does the rest, so a sweep's main()
// drops to roughly forty lines. Behavior is identical to the hand-rolled scaffolding; the
// live sweeps are the regression check.
package bench

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/internal/report"
	"github.com/t0ul/GORED/modelclient"
	gledger "github.com/t0ul/gledger"
	goserve "github.com/t0ul/goserve"
)

// Flags are the standard sweep flags. A cmd gets them with DefaultFlags, binds them with
// Register, then reads the parsed values (Bridge, Base, ...) when building its MakeRunner.
type Flags struct {
	Registry string
	Model    string
	ModelDir string
	Models   string
	Trials   int
	MaxSteps int
	MaxOut   int
	BasePort int
	Bridge   string
	Base     string
	Ensure   bool
	HTMLOut  string
	JSONOut  string
	Trace    string
	Wall     time.Duration
}

// DefaultFlags returns the defaults the stage-sweeps share.
func DefaultFlags() *Flags {
	return &Flags{
		Model:    "qwen2.5-3b-instruct.gguf",
		ModelDir: defaultModelDir(),
		Trials:   1,
		MaxSteps: 10,
		MaxOut:   512,
		BasePort: 12200,
		Bridge:   "127.0.0.1:5050",
		Base:     "http://127.0.0.1:8088",
		Ensure:   true,
		Trace:    "gored-sweep-trace.jsonl",
		Wall:     240 * time.Second,
	}
}

// Register binds the flags to fs, using the struct's current values as defaults. A cmd that
// needs extra flags registers them on the same FlagSet before Parse.
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.Registry, "registry", f.Registry, "model registry JSON")
	fs.StringVar(&f.Model, "model", f.Model, "default local GGUF")
	fs.StringVar(&f.ModelDir, "modeldir", f.ModelDir, "GGUF directory")
	fs.StringVar(&f.Models, "models", f.Models, "CSV of registry model names")
	fs.IntVar(&f.Trials, "trials", f.Trials, "trials per model")
	fs.IntVar(&f.MaxSteps, "steps", f.MaxSteps, "max loop steps")
	fs.IntVar(&f.MaxOut, "max-out", f.MaxOut, "max completion tokens per call")
	fs.IntVar(&f.BasePort, "base-port", f.BasePort, "first local model serve port")
	fs.StringVar(&f.Bridge, "bridge", f.Bridge, "Brig vsock bridge")
	fs.StringVar(&f.Base, "base", f.Base, "target base URL on the guest loopback")
	fs.BoolVar(&f.Ensure, "ensure", f.Ensure, "auto-(re)launch the target container if down; set false to target an already-running app")
	fs.StringVar(&f.HTMLOut, "html", f.HTMLOut, "write the HTML leaderboard here")
	fs.StringVar(&f.JSONOut, "json", f.JSONOut, "write results JSON here")
	fs.StringVar(&f.Trace, "trace", f.Trace, "gledger trace path")
	fs.DurationVar(&f.Wall, "wall", f.Wall, "per-trial wall-clock budget")
}

// MakeRunner builds one contender's runnable for a fresh target. bench supplies the
// accounting-wrapped client and its compute account (already registered with the sweep) and
// the shared audit log it opened; the callback wires the toolbox, skill, playbook and oracle
// and returns the Runner (set its Audit to the audit passed in so trace events are emitted).
type MakeRunner func(model string, cl *gored.AccountingClient, acct *gored.ComputeAccount, rt gored.RunTarget, audit *gledger.AuditLog) (gored.Runnable, error)

// Sweep is a configured bench run. The cmd fills the varying bits; Run does the scaffolding.
type Sweep struct {
	Flags  *Flags
	Goal   string
	FlagID string

	// Contender identity. Name is composed as "<NamePrefix>(<model>) {<Label>}" — matching the
	// stage-sweeps' literal "solo(...)" prefix — with Label the skill tag (e.g.
	// "recon-fingerprint-xss"). NamePrefix defaults to "solo"; Shape is the Contender.Shape
	// the leaderboard scores by (gored.ShapeSolo = "A-solo"), kept separate from the label.
	Label      string
	NamePrefix string
	Shape      gored.Shape
	Temp       gored.SkillTemp

	Make   MakeRunner
	Target func() (gored.RunTarget, error)

	// Output labels.
	Banner     string // printed above the table, e.g. "vulnapp recon->fingerprint->XSS"
	Title      string // leaderboard HTML title
	TargetName string // leaderboard target label
	Flag       string // leaderboard flag label
	Note       string // leaderboard note

	// OnTrial is called per trial; nil installs a default one-line logger.
	OnTrial func(gored.SweepResult)
	// StartMsg is logged once before the run; nil skips it.
	StartMsg string
}

// Run boots the needed local models, opens the audit, builds the contenders, runs the
// sweep, prints the table, and writes the JSON/HTML outputs. It returns the results so a
// caller can do more with them.
func (s *Sweep) Run(ctx context.Context) ([]gored.SweepResult, error) {
	f := s.Flags
	reg := loadRegistry(f.Registry, f.Model)
	models := splitCSV(f.Models)
	if len(models) == 0 {
		models = []string{reg.Names()[0]}
	}

	// Boot the local models that are needed, each on its own serve port.
	need := map[string]bool{}
	for _, n := range models {
		if sp, err := reg.Resolve(n); err == nil && sp.Local() {
			need[n] = true
		}
	}
	urls := map[string]string{}
	if len(need) > 0 {
		var ms []goserve.Model
		p := f.BasePort
		for name := range need {
			sp, _ := reg.Resolve(name)
			ms = append(ms, goserve.Model{Name: name, File: specFile(sp, f.Model), Port: p, Ctx: 4096})
			p++
		}
		cfg := goserve.Config{Dir: f.ModelDir, Reclaim: true, ReadyTimeout: 150 * time.Second, Stdout: io.Discard, Models: ms}
		if ok, msg := cfg.Available(); !ok {
			return nil, fmt.Errorf("local model(s) not available (%s)", msg)
		}
		h, err := goserve.Start(ctx, cfg)
		if err != nil {
			return nil, err
		}
		defer h.Close()
		for name := range need {
			urls[name] = h.ChatURL(name)
		}
	}

	audit, err := gledger.Open(f.Trace, "gored")
	if err != nil {
		return nil, err
	}
	clientFor := func(name string) (*gored.AccountingClient, *gored.ComputeAccount) {
		sp, _ := reg.Resolve(name)
		acct := gored.NewComputeAccount(sp)
		var inner gored.ModelClient
		if sp.Local() {
			inner = modelclient.New(urls[name], sp.ModelID())
		} else {
			inner = modelclient.FromSpec(sp)
		}
		return gored.NewAccountingClient(inner, acct), acct
	}

	shape := s.Shape
	if shape == "" {
		shape = gored.ShapeSolo
	}
	prefix := s.NamePrefix
	if prefix == "" {
		prefix = "solo"
	}
	var contenders []gored.Contender
	for _, m := range models {
		model := m
		contenders = append(contenders, gored.Contender{
			Name: fmt.Sprintf("%s(%s) {%s}", prefix, model, s.Label), Shape: shape, Temp: s.Temp,
			Build: func(rt gored.RunTarget) (gored.Runnable, []*gored.ComputeAccount, error) {
				cl, acct := clientFor(model)
				runnable, berr := s.Make(model, cl, acct, rt, audit)
				if berr != nil {
					return nil, nil, berr
				}
				return runnable, []*gored.ComputeAccount{acct}, nil
			},
		})
	}

	onTrial := s.OnTrial
	if onTrial == nil {
		onTrial = func(r gored.SweepResult) {
			log.Printf("  %-40s trial %d: %-8s via=%s tools=%d tokens=%d", r.Contender, r.Trial, r.Outcome, r.CapturedVia, r.ToolCalls, r.TokensIn+r.TokensOut)
		}
	}
	sweep := &gored.Sweep{
		Contenders: contenders, Target: s.Target, FlagID: s.FlagID,
		Goal: s.Goal, Trials: f.Trials, Audit: audit, OnTrial: onTrial,
	}
	if s.StartMsg != "" {
		log.Print(s.StartMsg)
	}
	results, err := sweep.Run(ctx)
	if err != nil {
		return nil, err
	}

	sums := gored.Summarize(results)
	fmt.Printf("\n==== %s ====\n%s", s.Banner, gored.Table(sums))
	fmt.Printf("trace: %s\n", f.Trace)
	if f.JSONOut != "" {
		b, _ := json.MarshalIndent(map[string]any{"summary": sums, "results": results}, "", "  ")
		if werr := os.WriteFile(f.JSONOut, b, 0o644); werr != nil {
			return results, werr
		}
	}
	if f.HTMLOut != "" {
		meta := report.LeaderboardMeta{Title: s.Title, Target: s.TargetName, Flag: s.Flag, Trials: f.Trials, Note: s.Note}
		if werr := os.WriteFile(f.HTMLOut, report.RenderLeaderboardHTML(meta, sums), 0o644); werr != nil {
			return results, werr
		}
		fmt.Printf("leaderboard HTML: %s\n", f.HTMLOut)
	}
	return results, nil
}

// Bounds builds the per-trial bounds from the flags.
func (f *Flags) Bounds() gored.Bounds {
	return gored.Bounds{MaxSteps: f.MaxSteps, Wall: f.Wall, MaxOutTokens: f.MaxOut}
}

// --- registry/model helpers (shared, previously copy-pasted per sweep) ---

func loadRegistry(path, def string) *gored.ModelRegistry {
	if path != "" {
		reg, err := gored.LoadRegistry(path)
		if err != nil {
			log.Fatal(err)
		}
		return reg
	}
	return gored.NewModelRegistry([]gored.ModelSpec{{Name: strings.TrimSuffix(filepath.Base(def), ".gguf"), GGUF: def, ParamsB: 3}})
}

func specFile(s gored.ModelSpec, fb string) string {
	if s.GGUF != "" {
		return s.GGUF
	}
	return fb
}

func splitCSV(s string) []string {
	var o []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			o = append(o, p)
		}
	}
	return o
}

func defaultModelDir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".riskrancher", "models")
}
