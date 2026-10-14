package core

import "github.com/t0ul/GORED/internal/ingest"

// Scanner/spec/source/runtime ingestion now lives in github.com/t0ul/GORED/internal/ingest
// (docs/GORED-ARCHITECTURE-PLAN.md, Phase 4). These aliases keep the gored.* surface stable
// for the root subsystems that consume ingested findings (correlate, validator, hunt,
// blackboard) and for the cmds, so the move is behavior-preserving. internal/ingest does not
// import the root package, so the edge runs one way (root -> ingest) with no cycle.

type (
	ScannerFinding   = ingest.ScannerFinding
	FindingCols      = ingest.FindingCols
	FindingSource    = ingest.FindingSource
	SQLFindingSource = ingest.SQLFindingSource
	APIPath          = ingest.APIPath
	SourceAnalyzer   = ingest.SourceAnalyzer
	RuntimeAnalyzer  = ingest.RuntimeAnalyzer
	ContainerIssue   = ingest.ContainerIssue
	Rung             = ingest.Rung
)

const (
	RungUnknown   = ingest.RungUnknown
	RungAbsent    = ingest.RungAbsent
	RungPresent   = ingest.RungPresent
	RungReachable = ingest.RungReachable
	RungRuledOut  = ingest.RungRuledOut
)

var (
	RiskRancherCols       = ingest.RiskRancherCols
	AnalyzeDockerfile     = ingest.AnalyzeDockerfile
	DetectAnalyzer        = ingest.DetectAnalyzer
	DetectRuntimeAnalyzer = ingest.DetectRuntimeAnalyzer
	PathsFromOpenAPI      = ingest.PathsFromOpenAPI
)

// Unexported forwarders for the ingest helpers the root subsystems (correlate, hunt,
// validator) still call by their bare names — exported from ingest, aliased here so those
// call sites are untouched.
var (
	modulePath          = ingest.ModulePath
	mergeSpecPaths      = ingest.MergeSpecPaths
	isDockerfileFinding = ingest.IsDockerfileFinding
)
