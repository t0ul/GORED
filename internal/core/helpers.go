package core

import "github.com/t0ul/GORED/internal/tools"

// asString, trunc and shellQuote are used across the root package (discover.go, loop.go,
// canaryseed.go, sweep.go, differential.go, verify.go). Their single implementation lives
// in internal/tools; these forward to it so the move leaves exactly one copy.

func asString(v any) string        { return tools.AsString(v) }
func trunc(s string, n int) string { return tools.Trunc(s, n) }
func shellQuote(s string) string   { return tools.ShellQuote(s) }
