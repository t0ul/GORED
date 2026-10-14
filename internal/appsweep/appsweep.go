// Package appsweep is the web-app security tester's run library: it drives one loop stage
// (recon | map | plan | exploit) against a local app over the Egress-gated Brig transport and
// returns the sweep results. It is the single in-process entry point both the gored-appsweep
// CLI and the EVA web cockpit call, so neither re-implements the run wiring. Each stage supplies
// only what varies — its toolbox, skill, playbook and oracle; bench does the scaffolding.
package appsweep

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/t0ul/GORED/internal/bench"
	"github.com/t0ul/GORED/internal/brig"
	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/internal/tools"
	gledger "github.com/t0ul/gledger"
	"github.com/t0ul/gobrig"
)

// canaryBeacon is a non-target host (the cloud-metadata SSRF address). It is never on the
// Egress allowlist, so the Runner's containment beacon is denied through the gated http_request
// tool every run — the observable proof that containment holds.
const canaryBeacon = "http://169.254.169.254/latest/meta-data/"

// Stage is one loop stage's varying wiring; bench + Run do the rest. Its fields are exported so
// the EVA cockpit can introspect a stage (its goal, label) for the UI.
type Stage struct {
	Label      string // skill tag, forms the contender name "solo(model) {label}"
	Goal       string
	Banner     string // table header
	Title      string // leaderboard title
	TargetName string
	Flag       string
	Note       string
	Skill      core.Skill
	Phases     func() []core.Phase
	Detect     func(toolResult string) (bool, string)
	// BuildTools wires the stage's toolbox over a gate bound to the target.
	BuildTools func(gate *tools.Gate, base string) *core.Toolbox
}

// Stages is the registry Run selects from, keyed by stage name.
func Stages() map[string]Stage {
	return map[string]Stage{
		"recon":   reconStage(),
		"map":     mapStage(),
		"plan":    planStage(),
		"exploit": exploitStage(),
	}
}

// StageNames lists the available stage names, sorted, for help text and the cockpit.
func StageNames() string {
	ns := make([]string, 0, len(Stages()))
	for n := range Stages() {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return strings.Join(ns, "|")
}

// Option configures a Run. The CLI passes none (fully autonomous); EVA passes
// WithCheckpoint to pilot the run interactively.
type Option func(*options)

type options struct {
	checkpoint       core.Checkpoint
	skillInstruction string
	goal             string
}

// WithCheckpoint installs a human-in-the-loop checkpoint on the stage's Runner, so the
// run pauses at each phase boundary for the pilot. Omitting it leaves the Runner fully
// autonomous — byte-for-byte the headless/CI path.
func WithCheckpoint(cp core.Checkpoint) Option {
	return func(o *options) { o.checkpoint = cp }
}

// WithSkillInstruction overrides the stage's skill instruction for this run — the first
// prompt knob of the control plane. Empty keeps the stage default.
func WithSkillInstruction(s string) Option {
	return func(o *options) { o.skillInstruction = s }
}

// WithGoal overrides the stage's objective line for this run. Empty keeps the stage default.
func WithGoal(s string) Option {
	return func(o *options) { o.goal = s }
}

// Run executes the named stage as a bench sweep against f.Base and returns the per-trial
// results. The CLI and the EVA cockpit both call this; it never calls os.Exit or parses flags.
func Run(ctx context.Context, f *bench.Flags, stageName string, opts ...Option) ([]core.SweepResult, error) {
	st, ok := Stages()[stageName]
	if !ok {
		return nil, fmt.Errorf("unknown stage %q; choose one of: %s", stageName, StageNames())
	}
	var o options
	for _, fn := range opts {
		fn(&o)
	}
	// Prompt knobs: override the stage's skill instruction / goal for this run. st is a
	// local copy of the registry entry, so this never mutates the shared stage.
	if o.skillInstruction != "" {
		st.Skill.Instruction = o.skillInstruction
	}
	if o.goal != "" {
		st.Goal = o.goal
	}
	bc := gobrig.Client{Bridge: f.Bridge}
	sw := &bench.Sweep{
		Flags:  f,
		Goal:   st.Goal,
		FlagID: "n/a",
		Label:  st.Label, Shape: core.ShapeSolo, Temp: core.SkillCold,
		Banner:     st.Banner,
		Title:      st.Title,
		TargetName: st.TargetName,
		Flag:       st.Flag,
		Note:       st.Note,
		StartMsg:   fmt.Sprintf("appsweep -stage %s vs %s, %d trials", stageName, f.Base, f.Trials),
		Target: func() (core.RunTarget, error) {
			if f.Ensure {
				if err := ensureVulnapp(bc, f.Base); err != nil {
					return core.RunTarget{}, err
				}
			}
			return core.RunTarget{Target: externalTarget{name: f.Base}, BaseURL: f.Base, Close: func() {}}, nil
		},
		Make: func(model string, cl *core.AccountingClient, acct *core.ComputeAccount, rt core.RunTarget, audit *gledger.AuditLog) (core.Runnable, error) {
			tr := brig.Transport{Bridge: f.Bridge, TraceID: stageName}
			gate := tools.NewGate(tr, tools.NewEgress(egressAuthority(f.Base)), func(u string) {
				log.Printf("  egress denied (off-target host blocked): %s", u)
			})
			return &core.Runner{
				Model: cl, Tools: st.BuildTools(gate, f.Base), Skill: st.Skill, Target: rt.Target,
				Board: core.NewUnscrubbedBlackboard(), Audit: audit, Bounds: f.Bounds(),
				Detector: st.Detect, Phases: st.Phases(), CanaryURL: canaryBeacon,
				Checkpoint: o.checkpoint,
			}, nil
		},
	}
	return sw.Run(ctx)
}

// gateAuthorities exposes a gate's allowlist so a stage's http_request tool can report it to the
// Runner for the denied-beacon log (the Runner reads EgressAuthorities off http_request).
func gateAuthorities(g *tools.Gate) []string {
	if g == nil || g.Egress() == nil {
		return nil
	}
	return g.Egress().Authorities()
}

// egressAuthority extracts the host:port from a base URL, for the Egress allowlist.
func egressAuthority(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return base
	}
	return u.Host
}

type externalTarget struct{ name string }

func (e externalTarget) Manifest() core.Manifest { return core.Manifest{Name: e.name} }
func (externalTarget) Status() []core.FlagStatus { return nil }

// ensureVulnapp makes sure the vulnapp container answers on the guest loopback before a trial.
// Stateless stages (XSS, recon) have no scoreboard to reset, so it only (re)launches when down.
func ensureVulnapp(c gobrig.Client, base string) error {
	for i := 0; i < 20; i++ {
		if r, err := c.Detonate(context.Background(), gobrig.Detonation{Argv: []string{"sh", "-c", "wget -qO- " + base + "/health 2>/dev/null"}, TraceID: "appsweep-up"}); err == nil && strings.Contains(r.Output, "ok") {
			return nil
		}
		if i == 0 {
			_, _ = c.Detonate(context.Background(), gobrig.Detonation{Argv: []string{"sh", "-c",
				"/mnt/assets/runc delete --force appsweep >/dev/null 2>&1; rm -rf /tmp/appsweep; cp -a /mnt/assets/bundle /tmp/appsweep; /mnt/assets/runc run -d --bundle /tmp/appsweep appsweep >/tmp/appsweep.log 2>&1 & echo launched"}, TraceID: "appsweep-up"})
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("vulnapp did not come up on %s", base)
}
