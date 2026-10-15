package eva

import (
	"os"
	"sort"
	"strings"

	"github.com/t0ul/GORED/internal/bench"
)

// listModels returns the chat GGUF files in the bench model directory, as the filenames the
// launch form expects, so the cockpit can offer the real local models as clickable chips and
// mark a "model present" preflight light. Embedding models (all-minilm) are filtered out.
func listModels() []string {
	ents, err := os.ReadDir(bench.DefaultFlags().ModelDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasSuffix(n, ".gguf") && !strings.Contains(n, "minilm") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
