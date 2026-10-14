package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Transport is the raw outbound mechanism a tool's network access runs over. Two
// implementations exist: DirectTransport (plain net/http, for an app reached on the
// host) and brig.Transport (a detonation inside the contained chamber). A tool never
// holds a Transport directly — it holds a *Gate, which authorizes the target against
// the Egress allowlist before delegating. That is how "every outbound request passes
// the gate" is a type boundary and not a convention: there is no field on a tool that
// reaches the network except through a Gate.
type Transport interface {
	// Fetch performs an HTTP GET of rawurl and returns the response body.
	Fetch(ctx context.Context, rawurl string) (string, error)
	// Detonate runs a scanner invocation (argv) that targets targetURL, returning its
	// combined output. targetURL is passed separately so the Gate can authorize the
	// host the scanner will reach even though it is embedded in argv.
	Detonate(ctx context.Context, targetURL string, argv []string) (string, error)
	// Describe is a short label for traces/logs, e.g. "brig(127.0.0.1:5050)".
	Describe() string
}

// Gate wraps a Transport with the Egress allowlist. Every Fetch/Detonate authorizes
// the target URL first; a denied host fires OnDeny (the beacon the loop records) and
// returns ErrEgressDenied WITHOUT touching the Transport. A nil Egress denies
// everything — fail-closed, so a mis-wired tool reaches nothing rather than the world.
type Gate struct {
	egress *Egress
	onDeny func(rawurl string)
	tr     Transport
}

// NewGate binds a transport to an allowlist and a deny beacon. onDeny may be nil.
func NewGate(tr Transport, e *Egress, onDeny func(string)) *Gate {
	return &Gate{tr: tr, egress: e, onDeny: onDeny}
}

// authorize is the single chokepoint: deny (and beacon) unless the Egress allows the
// URL. It runs before any delegation to the Transport, so a denied call never leaves
// the box.
func (g *Gate) authorize(rawurl string) error {
	if g.egress == nil || !g.egress.Allowed(rawurl) {
		if g.onDeny != nil {
			g.onDeny(rawurl)
		}
		return fmt.Errorf("%w: %s", ErrEgressDenied, rawurl)
	}
	return nil
}

// Fetch authorizes rawurl, then delegates to the transport's GET.
func (g *Gate) Fetch(ctx context.Context, rawurl string) (string, error) {
	if err := g.authorize(rawurl); err != nil {
		return "", err
	}
	return g.tr.Fetch(ctx, rawurl)
}

// Detonate authorizes targetURL, then delegates the scanner invocation to the transport.
func (g *Gate) Detonate(ctx context.Context, targetURL string, argv []string) (string, error) {
	if err := g.authorize(targetURL); err != nil {
		return "", err
	}
	return g.tr.Detonate(ctx, targetURL, argv)
}

// Egress returns the allowlist the gate enforces (for logging its authorities).
func (g *Gate) Egress() *Egress { return g.egress }

// Describe reports the underlying transport, for traces.
func (g *Gate) Describe() string {
	if g.tr == nil {
		return "gate(no transport)"
	}
	return "gate(" + g.tr.Describe() + ")"
}

// DirectTransport reaches an app on the host over plain net/http. It fetches pages,
// but it cannot detonate a scanner: scanner detonation runs only inside the Brig's
// contained chamber, so Detonate reports that rather than shelling a network binary
// out on the host. It exists so the generic Get/Fingerprint/JSEndpoints tools are not
// Brig-locked (a plain localhost app needs no chamber to be crawled).
type DirectTransport struct {
	Client *http.Client // nil uses a 30s client
}

func (d DirectTransport) client() *http.Client {
	if d.Client != nil {
		return d.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (d DirectTransport) Fetch(ctx context.Context, rawurl string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// 8 MiB comfortably covers a single-page app's main bundle (what js_endpoints reads)
	// while bounding memory against a runaway response.
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return string(data), nil
}

func (DirectTransport) Detonate(_ context.Context, _ string, _ []string) (string, error) {
	return "", fmt.Errorf("direct transport cannot detonate a scanner: scanner detonation runs only in the Brig's contained chamber")
}

func (DirectTransport) Describe() string { return "direct(net/http)" }

// interface checks
var _ Transport = DirectTransport{}
