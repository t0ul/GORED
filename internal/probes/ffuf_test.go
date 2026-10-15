package probes

import (
	"context"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/t0ul/GORED/demotarget"
	"github.com/t0ul/GORED/internal/tools"
)

// Real system, real scanner: run the actual ffuf binary through the real Gate+transport against the
// demotarget. The vulnerable build serves a leftover /backup.zip at an UNLINKED path, so content
// discovery must find it; the hardened build 404s it, so discovery must not. The server's own 200/404
// is the oracle. Skips if the ffuf binary is not provisioned (asset-gated, like the other scanners).
func ffufBinOrSkip(t *testing.T) string {
	t.Helper()
	bin := tools.DefaultFfufBin()
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("ffuf binary not provisioned at %s; skipping live content-discovery test", bin)
	}
	return bin
}

func TestFfufDiscoversUnlinkedBackupLive(t *testing.T) {
	bin := ffufBinOrSkip(t)
	base, done := startDemotarget(t)
	defer done()
	fs, err := (tools.FfufScanTool{Gate: demoGate(t, base), Base: base, Bin: bin}).Scan(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	var found *tools.FfufFinding
	for i := range fs {
		if fs[i].Path == "backup.zip" {
			found = &fs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("ffuf should discover the unlinked /backup.zip on the vulnerable build; got: %+v", fs)
	}
	// The proof adapter must classify the leftover archive as a sensitive-file exposure.
	p, ok := ProofFromFfuf(*found, "demotarget")
	if !ok || p.CWE != "CWE-530" {
		t.Fatalf("backup.zip should normalize to a CWE-530 exposure proof; got ok=%v cwe=%q", ok, p.CWE)
	}
}

func TestFfufHardenedNoBackupLive(t *testing.T) {
	bin := ffufBinOrSkip(t)
	srv, err := demotarget.New(demotarget.WithHardened())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()
	base := "http://" + ln.Addr().String()
	fs, err := (tools.FfufScanTool{Gate: demoGate(t, base), Base: base, Bin: bin}).Scan(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Path == "backup.zip" {
			t.Fatalf("hardened build must not serve /backup.zip (should 404); ffuf found: %+v", f)
		}
	}
}
