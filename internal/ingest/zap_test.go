package ingest

import (
	"strings"
	"testing"
)

// Pure logic: parse a representative ZAP JSON report. riskcode maps to a severity word, cweid to a
// CWE, the first instance URI to the Location (path only, so it correlates with runtime findings),
// and the solution to the remediation. An XXE alert is the class ZAP adds over nuclei.
func TestParseZAPReport(t *testing.T) {
	data := []byte(`{"@version":"2.14.0","site":[{"@name":"http://app.test","@host":"app.test","alerts":[
	  {"alert":"XML External Entity Attack","name":"XML External Entity Attack","riskcode":"3","cweid":"611",
	   "desc":"<p>An XXE was found.</p>","solution":"<p>Disable external entities.</p>","count":"1",
	   "instances":[{"uri":"http://app.test/api/import","method":"POST","param":"body"}]},
	  {"alert":"Missing Anti-clickjacking Header","name":"Missing Anti-clickjacking Header","riskcode":"2","cweid":"1021",
	   "desc":"X-Frame-Options missing","solution":"Set X-Frame-Options","count":"5",
	   "instances":[{"uri":"http://app.test/","method":"GET","param":""}]}
	]}]}`)
	fs := ParseZAPReport(data, "app")
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(fs), fs)
	}
	xxe := fs[0]
	if xxe.Source != "ZAP" || xxe.App != "app" || xxe.CWE != "CWE-611" || xxe.Severity != "high" {
		t.Fatalf("XXE finding fields wrong: %+v", xxe)
	}
	if xxe.Location != "/api/import" {
		t.Fatalf("location should be the instance URI path, got %q", xxe.Location)
	}
	if !strings.Contains(xxe.Remediation, "Disable external entities") {
		t.Fatalf("solution should become the remediation (HTML stripped): %q", xxe.Remediation)
	}
	cj := fs[1]
	if cj.Severity != "medium" || cj.CWE != "CWE-1021" {
		t.Fatalf("clickjacking finding fields wrong: %+v", cj)
	}
	if !strings.Contains(cj.Title, "5 instances") {
		t.Fatalf("multi-instance count should be in the title: %q", cj.Title)
	}
}
