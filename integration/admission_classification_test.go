//go:build admission

package integration

import "testing"

func TestAdmissionClassification(t *testing.T) {
	denial := `Error from server: admission webhook "policy.sigstore.dev" denied the request: `
	for _, tc := range []struct {
		name, output, want string
		code               int
	}{
		{"accepted-pod", `{"kind":"Pod"}`, "allowed", 0},
		{"accepted-deployment", `{"kind":"Deployment"}`, "allowed", 0},
		{"unsigned", denial + "no signatures found", "signature-denied", 1},
		{"wrong-identity", denial + "none of the expected identities matched", "identity-denied", 1},
		{"no-policy", denial + "no matching policies", "no-policy-denied", 1},
		{"verifier-outage", `failed calling webhook "policy.sigstore.dev": no endpoints available`, "unavailable", 1},
		{"webhook-timeout", `failed calling webhook "policy.sigstore.dev": context deadline exceeded`, "unavailable", 1},
		{"schema-error", "Pod is invalid: spec.ephemeralContainers.resources: Forbidden", "other", 1},
		{"pod-security-error", "violates PodSecurity restricted", "other", 1},
		{"client-timeout", "unable to connect to the server: i/o timeout", "other", 1},
		{"registry-timeout", denial + "no matching signatures: context deadline exceeded", "other", 1},
		{"unrelated-webhook", `admission webhook "other.invalid" denied the request: no signatures found`, "other", 1},
		{"unstructured-success", "created", "other", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyAdmission(tc.code, tc.output); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}
