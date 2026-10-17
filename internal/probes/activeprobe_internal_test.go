package probes

import (
	"testing"

	"github.com/chromedp/cdproto/network"
)

// interestingHeaders keeps only the security-relevant request header NAMES — the content type and any
// auth/CSRF header a probe must carry — and drops the browser's ambient noise.
func TestInterestingHeaders(t *testing.T) {
	h := network.Headers{
		"Content-Type":     "application/json",
		"Authorization":    "Bearer x",
		"X-CSRF-Token":     "tok",
		"X-XSRF-TOKEN":     "tok2",
		"X-Requested-With": "XMLHttpRequest", // ambient — must be dropped
		"Accept":           "*/*",            // ambient — must be dropped
		"User-Agent":       "chrome",         // ambient — must be dropped
	}
	got := map[string]bool{}
	for _, k := range interestingHeaders(h) {
		got[k] = true
	}
	for _, want := range []string{"Content-Type", "Authorization", "X-CSRF-Token", "X-XSRF-TOKEN"} {
		if !got[want] {
			t.Errorf("want %q kept", want)
		}
	}
	for _, drop := range []string{"X-Requested-With", "Accept", "User-Agent"} {
		if got[drop] {
			t.Errorf("want %q dropped", drop)
		}
	}
	if len(got) != 4 {
		t.Errorf("want exactly 4 interesting headers, got %d: %v", len(got), got)
	}
}
