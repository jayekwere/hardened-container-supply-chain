//go:build kubernetes

package integration

import "testing"

func TestProbeClassification(t *testing.T) {
	for _, tc := range []struct {
		name           string
		result         probeResult
		code           int
		allowed, match bool
	}{
		{"healthy-allowed", probeResult{ExpectedIP: "10.244.0.2", Reachable: true, Outcome: "reachable"}, 0, true, true},
		{"timeout-denied", probeResult{ExpectedIP: "10.244.0.2", Outcome: "timeout"}, 10, false, true},
		{"missing-agent-leaks-traffic", probeResult{ExpectedIP: "10.244.0.2", Reachable: true, Outcome: "reachable"}, 0, false, false},
		{"infrastructure-error-is-not-denial", probeResult{ExpectedIP: "10.244.0.2", Outcome: "error"}, 20, false, false},
		{"wrong-namespace-is-not-denial", probeResult{ExpectedIP: "10.244.0.3", Outcome: "timeout"}, 10, false, false},
		{"contradictory-exit-is-not-denial", probeResult{ExpectedIP: "10.244.0.2", Outcome: "timeout"}, 0, false, false},
		{"outage-breaks-positive-control", probeResult{ExpectedIP: "10.244.0.2", Outcome: "timeout"}, 10, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := probeMatches(tc.result, tc.code, "10.244.0.2", tc.allowed); got != tc.match {
				t.Fatalf("match=%t want=%t", got, tc.match)
			}
		})
	}
}
