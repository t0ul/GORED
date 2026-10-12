// Command gored-hunt is the generic, end-to-end in-house pentest for broken access
// control: point it at any local app, give it two identities, and it maps the
// authenticated surface, flags authorization weaknesses by differential comparison
// (no planted canary), has a LOCAL model write a repro the system executes to
// confirm each one, and emits a report plus a replayable trace. It holds no
// app-specific code — the app is named only by -url, the identities, and the login
// path — so the same binary runs against RiskRancher, the demo target, or anything
// else you are building locally.
//
// Identities come in two shapes, so cookie-login and header-token apps both work:
//
//	-priv user@app:pw -low other@app:pw     (JSON login at -login-path)
//	-priv-header 'X-Session: admin' -low-header 'X-Session: alice'
//
// Everything is contained (egress allowlisted to the target), read-only, and runs on
// local models; Claude writes no exploit and no repro.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	gored "github.com/t0ul/GORED"
	"github.com/t0ul/GORED/modelclient"
	gledger "github.com/t0ul/gledger"
	goserve "github.com/t0ul/goserve"
)

func main() {
	var (
		url        = flag.String("url", "http://127.0.0.1:8080", "local app to hunt")
		priv       = flag.String("priv", "", "privileged identity creds email:password (JSON login)")
		low        = flag.String("low", "", "low-privilege identity creds email:password (JSON login)")
		privHeader = flag.String("priv-header", "", "privileged identity as a static header 'Name: value' (instead of -priv)")
		lowHeader  = flag.String("low-header", "", "low-privilege identity as a static header 'Name: value' (instead of -low)")
		loginPath  = flag.String("login-path", "/api/auth/login", "login endpoint for creds identities")
		loginType  = flag.String("login-type", "json", "login body encoding: json | form")
		loginUser  = flag.String("login-user", "email", "login field name for the username/email")
		loginPass  = flag.String("login-pass", "password", "login field name for the password")
		start      = flag.String("start", "/", "discovery start path")
		modelF     = flag.String("model", "qwen2.5-3b-instruct.gguf", "local verifier model GGUF")
		modelDir   = flag.String("modeldir", defaultModelDir(), "GGUF directory")
		modelPort  = flag.Int("model-port", 11630, "verifier model server port")
		noVerify   = flag.Bool("no-verify", false, "skip the model; report flags UNVERIFIED")
		seed       = flag.Bool("seed", false, "plant canaries as the privileged identity first (6c), so a disclosed marker is a certain finding")
		outP       = flag.String("out", "gored-hunt-report.json", "write the JSON report here")
		traceP     = flag.String("trace", "gored-hunt-trace.jsonl", "replayable gledger trace")
	)
	flag.Parse()
	ctx := context.Background()

	egress := gored.NewEgress(hostPort(*url))
	httpTool := gored.NewHTTPRequestTool(*url, egress, nil)
	httpTool.AllowMethods = map[string]bool{"GET": true, "POST": true}

	login := loginSpec{path: *loginPath, kind: *loginType, userField: *loginUser, passField: *loginPass}
	privID := mustIdentity(ctx, httpTool, "priv", *priv, *privHeader, login)
	lowID := mustIdentity(ctx, httpTool, "low", *low, *lowHeader, login)

	audit, err := gledger.Open(*traceP, "gored")
	must(err)

	h := &gored.Hunt{
		Base: *url, Egress: egress, Sessions: httpTool.Sessions,
		Priv: privID, Low: lowID, Anon: &gored.Identity{Name: "anon", Session: "anon"},
		Audit: audit, Start: *start,
	}

	if !*noVerify {
		cfg := goserve.Config{
			Dir: *modelDir, Reclaim: true, ReadyTimeout: 150 * time.Second, Stdout: io.Discard,
			Models: []goserve.Model{{Name: "verifier", File: *modelF, Port: *modelPort, Ctx: 4096}},
		}
		if ok, msg := cfg.Available(); !ok {
			log.Fatalf("local model unavailable (%s); pass -no-verify to hunt without confirmation", msg)
		}
		hh, err := goserve.Start(ctx, cfg)
		must(err)
		defer hh.Close()
		h.Model = modelclient.New(hh.ChatURL("verifier"), name(*modelF))
	}

	if *seed {
		h.Seeder = &gored.CanarySeeder{
			Base: *url, Egress: egress, Sessions: httpTool.Sessions, Priv: privID, Model: h.Model, Audit: audit,
		}
	}

	rep, err := h.Run(ctx)
	must(err)

	must(writeReport(*outP, rep))
	printSummary(rep, *outP, *traceP)
}

// loginSpec says how a creds identity authenticates: the endpoint, the body encoding
// (json or form), and the field names for the username/email and password. This is
// what makes the tool generic across apps that don't use JSON email/password.
type loginSpec struct {
	path, kind, userField, passField string
}

// body renders the login request body and its content type for a user:pass pair.
func (s loginSpec) body(user, pass string) (string, string) {
	if s.kind == "form" {
		return url.Values{s.userField: {user}, s.passField: {pass}}.Encode(), "application/x-www-form-urlencoded"
	}
	return fmt.Sprintf("{%q:%q,%q:%q}", s.userField, user, s.passField, pass), "application/json"
}

// mustIdentity builds an identity from either creds (and logs it in so its cookie
// jar is live) or a static header. One of creds/header must be set.
func mustIdentity(ctx context.Context, tool *gored.HTTPRequestTool, name, creds, header string, login loginSpec) gored.Identity {
	switch {
	case creds != "":
		user, pass, ok := strings.Cut(creds, ":")
		if !ok {
			log.Fatalf("-%s must be user:password", name)
		}
		body, ct := login.body(user, pass)
		out, err := tool.Call(ctx, map[string]any{
			"method": "POST", "path": login.path, "session": name,
			"headers": map[string]any{"Content-Type": ct}, "body": body,
		})
		if err != nil || !strings.Contains(out, "HTTP 200") {
			log.Fatalf("login %s failed: %v\n%s", name, err, out)
		}
		return gored.Identity{Name: name, Session: name, LoginPath: login.path, LoginBody: body, LoginContentType: ct}
	case header != "":
		k, v, ok := strings.Cut(header, ":")
		if !ok {
			log.Fatalf("-%s-header must be 'Name: value'", name)
		}
		return gored.Identity{Name: name, Session: name, Headers: map[string]string{strings.TrimSpace(k): strings.TrimSpace(v)}}
	default:
		log.Fatalf("give -%s <email:password> or -%s-header 'Name: value'", name, name)
		return gored.Identity{}
	}
}

func writeReport(path string, rep gored.HuntReport) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	// Each confirmed finding's model-written, execution-validated repro, next to the report.
	dir := filepath.Dir(path)
	n := 0
	for _, f := range rep.Findings {
		if f.Confirmed && f.ReproGo != "" {
			n++
			_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("gored-hunt-repro-%d.go", n)), []byte(f.ReproGo), 0o644)
		}
	}
	return nil
}

func printSummary(rep gored.HuntReport, outP, traceP string) {
	fmt.Printf("\n==== gored-hunt: %s ====\n", rep.Target)
	fmt.Printf("surface: %d testable resource(s) discovered\n", rep.SurfaceCount)
	if len(rep.Findings) == 0 {
		fmt.Printf("no broken-access-control candidates flagged\n")
	}
	for _, f := range rep.Findings {
		status := "UNVERIFIED (no model)"
		if f.Confirmed {
			status = "CONFIRMED (repro reproduced)"
		} else if f.Verified {
			status = "UNCONFIRMED (repro did not reproduce)"
		}
		fmt.Printf("  [%s] %s %s — confidence=%s, %s\n      %s\n", f.CWE, f.Method, f.Path, f.Confidence, status, f.Evidence)
	}
	fmt.Printf("\nconfirmed=%d unconfirmed=%d unverified=%d\n", rep.Confirmed, rep.Unconfirmed, rep.Unverified)
	fmt.Printf("report: %s\nreplayable trace: %s\n  replay: gored-replay -trace %s\n", outP, traceP, traceP)
}

func hostPort(base string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
func name(file string) string { return strings.TrimSuffix(filepath.Base(file), ".gguf") }
func defaultModelDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".riskrancher", "models")
}
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
