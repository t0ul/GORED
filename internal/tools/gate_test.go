package tools

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// tripwireTransport fails the test if the Gate ever delegates to it. It is not a mock of
// transport behavior — it is a tripwire that proves the deny path short-circuits BEFORE any
// outbound call, i.e. that containment is a type boundary: a denied URL never reaches the
// network.
type tripwireTransport struct{ t *testing.T }

func (x tripwireTransport) Fetch(context.Context, string) (string, error) {
	x.t.Helper()
	x.t.Fatal("transport.Fetch was reached on a denied URL — the gate did not short-circuit")
	return "", nil
}
func (x tripwireTransport) Detonate(context.Context, string, []string) (string, error) {
	x.t.Helper()
	x.t.Fatal("transport.Detonate was reached on a denied URL — the gate did not short-circuit")
	return "", nil
}
func (x tripwireTransport) Request(context.Context, string, string, map[string]string, string) (int, string, error) {
	x.t.Helper()
	x.t.Fatal("transport.Request was reached on a denied URL — the gate did not short-circuit")
	return 0, "", nil
}
func (tripwireTransport) Describe() string { return "tripwire" }

func TestGateDeniesOffAllowlistAndBeacons(t *testing.T) {
	var denied []string
	g := NewGate(tripwireTransport{t}, NewEgress("127.0.0.1:8088"), func(u string) { denied = append(denied, u) })

	bad := "http://169.254.169.254/latest/meta-data/" // cloud-metadata SSRF beacon, off-allowlist
	if _, err := g.Fetch(context.Background(), bad); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("Fetch off-allowlist: err=%v, want ErrEgressDenied", err)
	}
	if _, err := g.Detonate(context.Background(), bad, []string{"dalfox", "scan", bad}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("Detonate off-allowlist: err=%v, want ErrEgressDenied", err)
	}
	if _, _, err := g.Request(context.Background(), "POST", bad, map[string]string{"X": "y"}, "{}"); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("Request off-allowlist: err=%v, want ErrEgressDenied", err)
	}
	if len(denied) != 3 {
		t.Fatalf("OnDeny beacon fired %d times, want 3 (one per denied call)", len(denied))
	}
}

func TestGateFailsClosedWithoutEgress(t *testing.T) {
	// A nil allowlist must deny everything, so a mis-wired tool reaches nothing.
	g := NewGate(tripwireTransport{t}, nil, nil)
	if _, err := g.Fetch(context.Background(), "http://127.0.0.1:8088/"); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("nil egress must fail closed: err=%v", err)
	}
}

func TestGateAllowsListedHostThroughRealTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello from app"))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Allow exactly this server's authority, keyed the same way Egress.Allowed looks it up.
	g := NewGate(DirectTransport{}, NewEgress(u.Hostname()+":"+u.Port()), nil)

	body, err := g.Fetch(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatalf("allowed Fetch through the real transport errored: %v", err)
	}
	if !strings.Contains(body, "hello from app") {
		t.Fatalf("allowed Fetch body = %q, want it to contain the server's response", body)
	}
}
