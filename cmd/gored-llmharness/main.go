// Command gored-llmharness runs the benign LLM target: a web app that wraps a real local
// model behind a fixed system prompt holding a planted secret, exposing an OpenAI-style chat
// path. Point it at a running model's chat-completions URL (e.g. modeld / goserve), then aim
// EVA's llmattack stage at this harness to exercise prompt injection and system-prompt leak.
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/t0ul/GORED/internal/core"
	"github.com/t0ul/GORED/llmharness"
	"github.com/t0ul/GORED/modelclient"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8090", "listen address")
	modelURL := flag.String("model-url", "http://127.0.0.1:11435/v1/chat/completions", "OpenAI-style chat-completions URL of the backing model")
	modelID := flag.String("model-id", "local", "model id to send to the backing model")
	hardened := flag.Bool("hardened", false, "serve the defended build (scrubs the secret)")
	flag.Parse()

	var client core.ModelClient = modelclient.New(*modelURL, *modelID)
	var opts []llmharness.Option
	if *hardened {
		opts = append(opts, llmharness.WithHardened())
	}
	srv, err := llmharness.New(client, opts...)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("llmharness on http://%s (model %s @ %s, hardened=%v)", *addr, *modelID, *modelURL, *hardened)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
