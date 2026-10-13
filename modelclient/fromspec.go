package modelclient

import gored "github.com/t0ul/GORED"

// FromSpec builds an OpenAI-compatible client from a registry spec's endpoint and model id.
// A remote spec carries its Endpoint directly; a local (GGUF) spec is booted first by
// goserve and the served ChatURL is put on the spec's Endpoint before calling FromSpec, so
// this one constructor covers both and the runtime stays model-agnostic.
func FromSpec(spec gored.ModelSpec) *OpenAI {
	return New(spec.Endpoint, spec.ModelID())
}
