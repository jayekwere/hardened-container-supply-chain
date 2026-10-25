package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func scanFixture(t *testing.T, name string) Report {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestScanGate(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	dir := filepath.Join(root, "docs", "exceptions")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "synthetic.md"), []byte(strings.Repeat("Synthetic evidence for regression testing; never a real vulnerability disposition. ", 3)), 0600); err != nil {
		t.Fatal(err)
	}
	entry := Exception{ID: "CVE-2099-0001", Package: "stdlib", Version: "v0.0.0-synthetic", Digest: testDigest, Created: now.Add(-time.Hour).Format(time.RFC3339), Expires: now.Add(time.Hour).Format(time.RFC3339), Owner: "maintainer", Reason: "Synthetic time-limited exception used only to verify exact matching and expiry behavior.", Evidence: "docs/exceptions/synthetic.md"}
	empty := Exceptions{SchemaVersion: 1, Entries: []Exception{}}
	for _, tc := range []struct {
		name   string
		modify func(*Report, *Exceptions)
		allow  bool
	}{
		{"clean", func(r *Report, e *Exceptions) { *r = scanFixture(t, "scan-clean.json") }, true},
		{"high-denied", func(r *Report, e *Exceptions) {}, false},
		{"valid-high-exception", func(r *Report, e *Exceptions) { e.Entries = []Exception{entry} }, true},
		{"critical-never-excepted", func(r *Report, e *Exceptions) {
			e.Entries = []Exception{entry}
			r.Results[0].Vulnerabilities[0].Severity = "CRITICAL"
		}, false},
		{"unknown", func(r *Report, e *Exceptions) { r.Results[0].Vulnerabilities[0].Severity = "UNKNOWN" }, false},
		{"empty-inventory", func(r *Report, e *Exceptions) { r.Results = nil }, false},
		{"wrong-image", func(r *Report, e *Exceptions) { r.Metadata.ImageID = "sha256:bad" }, false},
		{"expired", func(r *Report, e *Exceptions) {
			x := entry
			x.Expires = now.Format(time.RFC3339)
			e.Entries = []Exception{x}
		}, false},
		{"future-created", func(r *Report, e *Exceptions) {
			x := entry
			x.Created = now.Add(time.Minute).Format(time.RFC3339)
			e.Entries = []Exception{x}
		}, false},
		{"overlong", func(r *Report, e *Exceptions) {
			x := entry
			x.Expires = now.Add(15 * 24 * time.Hour).Format(time.RFC3339)
			e.Entries = []Exception{x}
		}, false},
		{"wrong-digest", func(r *Report, e *Exceptions) { x := entry; x.Digest = "sha256:other"; e.Entries = []Exception{x} }, false},
		{"wrong-version", func(r *Report, e *Exceptions) { x := entry; x.Version = "other"; e.Entries = []Exception{x} }, false},
		{"missing-evidence", func(r *Report, e *Exceptions) {
			x := entry
			x.Evidence = "docs/exceptions/missing.md"
			e.Entries = []Exception{x}
		}, false},
		{"traversal", func(r *Report, e *Exceptions) {
			x := entry
			x.Evidence = "docs/exceptions/../../../secret"
			e.Entries = []Exception{x}
		}, false},
		{"duplicate", func(r *Report, e *Exceptions) { e.Entries = []Exception{entry, entry} }, false},
		{"unused", func(r *Report, e *Exceptions) { *r = scanFixture(t, "scan-clean.json"); e.Entries = []Exception{entry} }, false},
		{"schema", func(r *Report, e *Exceptions) { r.SchemaVersion = 1 }, false},
		{"missing-id", func(r *Report, e *Exceptions) { r.Results[0].Vulnerabilities[0].VulnerabilityID = "" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := scanFixture(t, "scan-high.json")
			e := empty
			tc.modify(&r, &e)
			blocked, _ := Scan(r, e, testDigest, testDigest, root, now)
			if (len(blocked) == 0) != tc.allow {
				t.Fatalf("allow=%t blocked=%v", tc.allow, blocked)
			}
		})
	}
}
func TestExceptionDecoding(t *testing.T) {
	for _, raw := range []string{`{"schemaVersion":1,"entries":[],"ignoreAll":true}`, `{} {}`, `null x`} {
		if _, err := DecodeExceptions([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err := DecodeExceptions([]byte(`{"schemaVersion":1,"entries":[]}`)); err != nil {
		t.Fatal(err)
	}
}
