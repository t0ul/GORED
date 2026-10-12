package gored

import (
	"strings"
	"testing"
)

func TestClassifyStatus(t *testing.T) {
	cases := map[int]string{
		200: "ok",
		302: "redirect",
		401: "auth",
		403: "auth",
		429: "rate-limited",
		500: "server error",
		404: "client error",
	}
	for status, want := range cases {
		if got := classifyStatus(status); !strings.Contains(got, want) {
			t.Errorf("classifyStatus(%d) = %q, want it to mention %q", status, got, want)
		}
	}
}
