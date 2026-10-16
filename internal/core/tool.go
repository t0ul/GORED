package core

import "github.com/t0ul/GORED/internal/tools"

// The canonical agent tool layer now lives in github.com/t0ul/GORED/internal/tools
// (docs/GORED-ARCHITECTURE-PLAN.md, Phase 1). These aliases and forwarders keep the
// gored.* surface stable for existing callers — loop.go, the probes, and the ~24 cmds —
// so the move is behavior-preserving. New code should import internal/tools directly.

type (
	Tool            = tools.Tool
	Toolbox         = tools.Toolbox
	Egress          = tools.Egress
	Sessions        = tools.Sessions
	HTTPRequestTool = tools.HTTPRequestTool
	ExecTool        = tools.ExecTool
	DiffTool        = tools.DiffTool
	LoginSpec       = tools.LoginSpec
)

var (
	NewToolbox         = tools.NewToolbox
	NewEgress          = tools.NewEgress
	NewSessions        = tools.NewSessions
	NewHTTPRequestTool = tools.NewHTTPRequestTool
	NewExecTool        = tools.NewExecTool
	CurlFor            = tools.CurlFor

	// ErrEgressDenied is the same sentinel value as tools.ErrEgressDenied, so
	// errors.Is(err, ErrEgressDenied) and fmt.Errorf("%w", ErrEgressDenied, ...) in
	// loop.go/massassign.go/differential.go keep matching after the move.
	ErrEgressDenied = tools.ErrEgressDenied
)
