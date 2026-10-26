//go:build admission

package integration

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type policyWriteAttempt struct {
	Attempt   int      `json:"attempt"`
	Started   string   `json:"startedAtUTC"`
	Arguments []string `json:"arguments"`
	ExitCode  int      `json:"exitCode"`
	Output    string   `json:"output"`
}

func policyWebhookUnavailable(output string) bool {
	s := strings.ToLower(output)
	conversion := strings.Contains(s, "conversion webhook for policy.sigstore.dev/") && strings.Contains(s, "failed:")
	admission := strings.Contains(s, "failed calling webhook") && strings.Contains(s, ".clusterimagepolicy.sigstore.dev")
	if strings.Contains(s, "denied the request") || !(conversion || admission) {
		return false
	}
	for _, message := range []string{"eof", "connection refused", "context deadline exceeded", "tls handshake timeout", "i/o timeout"} {
		if strings.Contains(s, message) {
			return true
		}
	}
	return false
}

// Only idempotent administrative policy applies can retry, before acknowledgement.
// Workload admission probes never call this helper.
func applyPolicyCommand(command func([]byte, ...string) ([]byte, int), input []byte, pause func(time.Duration), args ...string) ([]byte, int, []policyWriteAttempt) {
	var object struct{ APIVersion, Kind string }
	isPolicy := len(args) > 0 && args[0] == "apply" && json.Unmarshal(input, &object) == nil && object.Kind == "ClusterImagePolicy" && strings.HasPrefix(object.APIVersion, "policy.sigstore.dev/")
	attempts := []policyWriteAttempt{}
	started := time.Now()
	for attempt := 1; ; attempt++ {
		at := time.Now().UTC().Format(time.RFC3339Nano)
		out, code := command(input, args...)
		if isPolicy {
			attempts = append(attempts, policyWriteAttempt{attempt, at, args, code, string(out)})
		}
		if !isPolicy || code == 0 || !policyWebhookUnavailable(string(out)) || attempt >= 10 || time.Since(started) >= 60*time.Second {
			return out, code, attempts
		}
		pause(time.Second)
	}
}

func TestPolicyWriteClassification(t *testing.T) {
	prefix := `conversion webhook for policy.sigstore.dev/v1alpha1, Kind=ClusterImagePolicy failed: `
	for _, tc := range []struct {
		name, output string
		retry        bool
	}{
		{"conversion-eof", prefix + "Post resource-conversion: EOF", true},
		{"policy-validation-eof", `failed calling webhook "validating.clusterimagepolicy.sigstore.dev": Post validating: EOF`, true},
		{"policy-defaulting-eof", `failed calling webhook "defaulting.clusterimagepolicy.sigstore.dev": Post defaulting: EOF`, true},
		{"workload-webhook-eof", `failed calling webhook "policy.sigstore.dev": EOF`, false},
		{"conversion-refused", prefix + "connection refused", true},
		{"conversion-timeout", prefix + "context deadline exceeded", true},
		{"real-denial", `admission webhook denied the request: ` + prefix + "EOF", false},
		{"client-eof", "unable to connect to the server: EOF", false},
		{"foreign-conversion", `conversion webhook for other.invalid/v1 failed: EOF`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if policyWebhookUnavailable(tc.output) != tc.retry {
				t.Fatal("incorrect administrative retry classification")
			}
		})
	}
}

func TestPolicyWriteRetries(t *testing.T) {
	policy := []byte(`{"apiVersion":"policy.sigstore.dev/v1beta1","kind":"ClusterImagePolicy"}`)
	unavailable := []byte(`conversion webhook for policy.sigstore.dev/v1alpha1, Kind=ClusterImagePolicy failed: EOF`)
	for _, tc := range []struct {
		name                              string
		input                             []byte
		successAfter, wantCalls, wantCode int
	}{
		{"recovers-before-ack", policy, 2, 2, 0},
		{"bounded-outage", policy, 100, 10, 1},
		{"workload-never-retried", []byte(`{"apiVersion":"v1","kind":"Pod"}`), 2, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			command := func(_ []byte, _ ...string) ([]byte, int) {
				calls++
				if calls >= tc.successAfter {
					return []byte("configured"), 0
				}
				return unavailable, 1
			}
			_, code, attempts := applyPolicyCommand(command, tc.input, func(time.Duration) {}, "apply", "-f", "-")
			if code != tc.wantCode || calls != tc.wantCalls {
				t.Fatalf("code %d calls %d", code, calls)
			}
			if tc.name == "recovers-before-ack" && len(attempts) != 2 {
				t.Fatal("every pre-acknowledgement attempt must be retained")
			}
		})
	}
}
