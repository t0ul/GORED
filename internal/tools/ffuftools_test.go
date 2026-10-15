package tools

import "testing"

// Pure logic: parse ffuf's newline-delimited JSON records, deduplicating by URL and pulling the
// FUZZ value, status, and size. Non-JSON lines (banner noise) are skipped.
func TestParseFfuf(t *testing.T) {
	out := `not json, ignore me
{"input":{"FFUFHASH":"abc","FUZZ":"backup.zip"},"position":1,"status":200,"length":58,"words":8,"lines":2,"url":"http://127.0.0.1:8080/backup.zip"}
{"input":{"FFUFHASH":"def","FUZZ":".git/config"},"position":2,"status":200,"length":120,"url":"http://127.0.0.1:8080/.git/config"}
{"input":{"FFUFHASH":"abc","FUZZ":"backup.zip"},"position":1,"status":200,"length":58,"url":"http://127.0.0.1:8080/backup.zip"}
{"input":{"FUZZ":"admin"},"status":401,"length":0,"url":"http://127.0.0.1:8080/admin"}`
	fs := ParseFfuf(out)
	if len(fs) != 3 {
		t.Fatalf("want 3 deduped findings, got %d: %+v", len(fs), fs)
	}
	if fs[0].Path != "backup.zip" || fs[0].Status != 200 || fs[0].Size != 58 {
		t.Fatalf("first finding parsed wrong: %+v", fs[0])
	}
	if fs[2].Status != 401 || fs[2].Path != "admin" {
		t.Fatalf("access-controlled hit parsed wrong: %+v", fs[2])
	}
}
