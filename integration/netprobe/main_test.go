package main

import "testing"

func TestProbeFailsClosed(t *testing.T) {
	for _, args := range [][]string{nil, {"not-an-ip", "http", "http://127.0.0.1:8080"}, {"192.0.2.1", "http", "http://127.0.0.1:8080"}, {"127.0.0.1", "unexpected", "target"}} {
		r, code := run(args)
		if code != 20 || r.Reachable || r.Outcome != "error" {
			t.Fatalf("%v: result=%+v code=%d", args, r, code)
		}
	}
}
