package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCLIErrorContract(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmp, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"unknown", "--file", tmp}, {"scan", "--file", tmp}, {"manifests", "--file", tmp}, {"manifests", "--file", "missing"}, {"manifests", "--no-such-flag"}} {
		if code := run(args); code != 2 {
			t.Fatalf("%v: got %d", args, code)
		}
	}
}
