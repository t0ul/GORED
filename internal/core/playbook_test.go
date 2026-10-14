package core

import "testing"

func TestWebInjectionPlaybookMilestones(t *testing.T) {
	pb := WebInjectionPlaybook()
	if len(pb) != 3 || pb[0].Name != "recon" || pb[2].Advance != nil {
		t.Fatalf("playbook shape wrong: %+v", pb)
	}
	b := NewBlackboard()

	// recon advances when a live 200 endpoint responds, not on an error.
	if pb[0].Advance(b, "wget: server returned error: HTTP/1.1 404 NOT FOUND") {
		t.Error("recon should not advance on a 404")
	}
	if !pb[0].Advance(b, "HTTP/1.1 200 OK\n<html>a page</html>") {
		t.Error("recon should advance on a 200")
	}

	// probe advances on real command output, NOT on a reflected payload (the decoy).
	if pb[1].Advance(b, "No results for: id; cat /etc/passwd") {
		t.Error("probe must NOT advance on reflected input (a decoy)")
	}
	if !pb[1].Advance(b, "uid=0(root) gid=0(root)") {
		t.Error("probe should advance on genuine command output")
	}
}
