package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ZAP ingestion. nuclei already covers most of ZAP's active-scan remit (SSTI, open redirect,
// exposure, misconfiguration), so GORED does not bundle or run the heavy ZAP daemon; instead it
// ingests a ZAP JSON report an operator produced, turning its alerts into ScannerFindings so the
// existing validate.Correlate/Validator seam fuses and ranks them with everything else — and so the
// classes ZAP adds over nuclei (notably XXE) fold in without new validation code. The report is
// untrusted input (a claim to validate), exactly like any other ScannerFinding source.

// zapReport is the subset of ZAP's traditional JSON report this adapter reads.
type zapReport struct {
	Site []struct {
		Name   string `json:"@name"`
		Host   string `json:"@host"`
		Alerts []struct {
			Alert     string `json:"alert"`
			Name      string `json:"name"`
			RiskCode  string `json:"riskcode"` // 0=Info 1=Low 2=Medium 3=High
			CWEID     string `json:"cweid"`
			Desc      string `json:"desc"`
			Solution  string `json:"solution"`
			Count     string `json:"count"`
			Instances []struct {
				URI    string `json:"uri"`
				Method string `json:"method"`
				Param  string `json:"param"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

// ParseZAPReport maps a ZAP JSON report to ScannerFindings, one per alert (the alert's first instance
// URI is the Location, so it correlates with runtime findings on the same route). riskcode maps to a
// severity word and cweid to a CWE; the solution becomes the remediation. Reachable stays nil.
func ParseZAPReport(data []byte, app string) []ScannerFinding {
	var rep zapReport
	if json.Unmarshal(data, &rep) != nil {
		return nil
	}
	var out []ScannerFinding
	for _, s := range rep.Site {
		for _, a := range s.Alerts {
			name := a.Name
			if name == "" {
				name = a.Alert
			}
			loc := s.Name // fall back to the site when an alert has no instance
			method := ""
			if len(a.Instances) > 0 {
				loc = a.Instances[0].URI
				method = a.Instances[0].Method
			}
			cwe := ""
			if n := strings.TrimSpace(a.CWEID); n != "" && n != "-1" {
				cwe = "CWE-" + n
			}
			title := name
			if a.Count != "" && a.Count != "1" {
				title = fmt.Sprintf("%s (%s instances)", name, a.Count)
			}
			out = append(out, ScannerFinding{
				Source:      "ZAP",
				App:         app,
				Location:    locationFromURI(loc),
				Asset:       app + ":" + locationFromURI(loc),
				Severity:    zapRiskWord(a.RiskCode),
				Title:       title,
				CWE:         cwe,
				Description: strings.TrimSpace(method + " " + loc + " — " + stripTags(a.Desc)),
				Remediation: stripTags(a.Solution),
			})
		}
	}
	return out
}

// zapRiskWord maps ZAP's numeric riskcode to a severity word.
func zapRiskWord(code string) string {
	switch strings.TrimSpace(code) {
	case "3":
		return "high"
	case "2":
		return "medium"
	case "1":
		return "low"
	case "0":
		return "info"
	default:
		return ""
	}
}

// locationFromURI reduces a full URL to its path (the shape Correlate keys on), leaving a non-URL
// location untouched.
func locationFromURI(uri string) string {
	if i := strings.Index(uri, "://"); i >= 0 {
		rest := uri[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return rest[j:]
		}
		return "/"
	}
	return uri
}

// stripTags removes the light HTML ZAP wraps its descriptions in, for a grid-safe line.
func stripTags(s string) string {
	s = strings.ReplaceAll(s, "<p>", " ")
	s = strings.ReplaceAll(s, "</p>", " ")
	for {
		i := strings.IndexByte(s, '<')
		j := strings.IndexByte(s, '>')
		if i < 0 || j <= i {
			break
		}
		s = s[:i] + s[j+1:]
	}
	return strings.Join(strings.Fields(s), " ")
}
