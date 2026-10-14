// Command gored-appsweep is the web-app security tester's single entry point: one binary
// that runs any loop stage against a local app via `-stage recon|map|plan|exploit`. It
// replaces the per-stage sweep binaries (gored-{recon,map,plan,xss}sweep), which each
// re-copied the same model-boot/registry/accounting scaffolding; that now lives in
// internal/bench, and each stage here supplies only what varies — its toolbox, skill,
// playbook and oracle. Every tool routes outbound through the Egress gate (internal/tools +
// internal/brig), so containment holds and an off-target request is a denied beacon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/internal/bench"
	"github.com/t0ul/GORED/internal/brig"
	"github.com/t0ul/GORED/internal/tools"
	gledger "github.com/t0ul/gledger"
	"github.com/t0ul/gobrig"
)

// canaryBeacon is a non-target host (the cloud-metadata SSRF address). It is never on the
// Egress allowlist, so the Runner's containment beacon is denied through the gated
// http_request tool every run — the observable proof that containment holds.
const canaryBeacon = "http://169.254.169.254/latest/meta-data/"

// stage is one loop stage's varying wiring; bench + the shared scaffolding below do the rest.
type stage struct {
	label      string // skill tag, forms the contender name "solo(model) {label}"
	goal       string
	banner     string // table header
	title      string // leaderboard title
	targetName string
	flag       string
	note       string
	skill      gored.Skill
	phases     func() []gored.Phase
	detect     func(toolResult string) (bool, string)
	// buildTools wires the stage's toolbox over a gate bound to the target.
	buildTools func(gate *tools.Gate, base string) *gored.Toolbox
}

// stages is the registry the -stage flag selects from.
func stages() map[string]stage {
	return map[string]stage{
		"recon":   reconStage(),
		"exploit": exploitStage(),
	}
}

func main() {
	f := bench.DefaultFlags()
	f.Trace = "gored-appsweep-trace.jsonl"
	stageF := flag.String("stage", "recon", "loop stage: "+stageNames())
	f.Register(flag.CommandLine)
	flag.Parse()

	reg := stages()
	st, ok := reg[*stageF]
	if !ok {
		log.Fatalf("unknown -stage %q; choose one of: %s", *stageF, stageNames())
	}

	ctx := context.Background()
	bc := gobrig.Client{Bridge: f.Bridge}

	sw := &bench.Sweep{
		Flags:  f,
		Goal:   st.goal,
		FlagID: "n/a",
		Label:  st.label, Shape: gored.ShapeSolo, Temp: gored.SkillCold,
		Banner:     st.banner,
		Title:      st.title,
		TargetName: st.targetName,
		Flag:       st.flag,
		Note:       st.note,
		StartMsg:   fmt.Sprintf("appsweep -stage %s vs %s, %d trials", *stageF, f.Base, f.Trials),
		Target: func() (gored.RunTarget, error) {
			if f.Ensure {
				if err := ensureVulnapp(bc, f.Base); err != nil {
					return gored.RunTarget{}, err
				}
			}
			return gored.RunTarget{Target: externalTarget{name: f.Base}, BaseURL: f.Base, Close: func() {}}, nil
		},
		Make: func(model string, cl *gored.AccountingClient, acct *gored.ComputeAccount, rt gored.RunTarget, audit *gledger.AuditLog) (gored.Runnable, error) {
			tr := brig.Transport{Bridge: f.Bridge, TraceID: *stageF}
			gate := tools.NewGate(tr, tools.NewEgress(egressAuthority(f.Base)), func(u string) {
				log.Printf("  egress denied (off-target host blocked): %s", u)
			})
			return &gored.Runner{
				Model: cl, Tools: st.buildTools(gate, f.Base), Skill: st.skill, Target: rt.Target,
				Board: gored.NewUnscrubbedBlackboard(), Audit: audit, Bounds: f.Bounds(),
				Detector: st.detect, Phases: st.phases(), CanaryURL: canaryBeacon,
			}, nil
		},
	}
	if _, err := sw.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

func stageNames() string {
	ns := make([]string, 0, len(stages()))
	for n := range stages() {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return strings.Join(ns, "|")
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

func (e externalTarget) Manifest() gored.Manifest { return gored.Manifest{Name: e.name} }
func (externalTarget) Status() []gored.FlagStatus { return nil }

// ensureVulnapp makes sure the vulnapp container answers on the guest loopback before a
// trial. Stateless stages (XSS, recon) have no scoreboard to reset, so it only (re)launches
// when the app is down.
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
