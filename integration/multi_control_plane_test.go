//go:build admission

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func admissionControlPlanes(t *testing.T) []string {
	t.Helper()
	name := os.Getenv("TEST_ADMISSION_KIND_NAME")
	if !strings.HasPrefix(name, "hsc-admission-") || strings.ContainsAny(name, "/ \n") {
		t.Fatal("disposable cluster required")
	}
	return []string{name + "-control-plane", name + "-control-plane2", name + "-control-plane3"}
}

// Loopback inside each named node bypasses the external API load balancer.
// The node's admin config supplies client credentials and CA verification.
func controlPlaneCommand(t *testing.T, node string, input []byte, args ...string) ([]byte, int) {
	t.Helper()
	found := false
	for _, allowed := range admissionControlPlanes(t) {
		if node == allowed {
			found = true
		}
	}
	if !found {
		t.Fatal("unexpected node")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := append([]string{"exec", "-i", node, "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "--server=https://127.0.0.1:6443", "--request-timeout=40s"}, args...)
	cmd := exec.CommandContext(ctx, "docker", command...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, 0
	}
	if e, ok := err.(*exec.ExitError); ok {
		return out, e.ExitCode()
	}
	t.Fatalf("direct API request: %v", err)
	return nil, -1
}

func TestMultiControlPlane(t *testing.T) {
	nodes := admissionControlPlanes(t)
	var inputs admissionInputs
	b, err := os.ReadFile("../integration/admission/inputs.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &inputs); err != nil {
		t.Fatal(err)
	}
	observations := []trustObservation{}
	outcome := "failed"
	t.Cleanup(func() {
		b, _ := json.MarshalIndent(map[string]any{"schemaVersion": 1, "outcome": outcome, "nodes": nodes, "observations": observations}, "", "  ")
		if err := os.WriteFile("../artifacts/admission/multi-control-plane.json", append(b, '\n'), 0600); err != nil {
			t.Error(err)
		}
	})
	probe := func(phase, node, image, expected string) {
		pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "multi-control-plane-probe", "namespace": "signature-demo"}, "spec": map[string]any{"automountServiceAccountToken": false, "schedulingGates": []any{map[string]string{"name": "hsc.test/admission-only"}}, "securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "seccompProfile": map[string]string{"type": "RuntimeDefault"}}, "containers": []any{map[string]any{"name": "service", "image": image, "securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}}}}}}
		raw, _ := json.Marshal(pod)
		deadline := time.Now().Add(120 * time.Second)
		for {
			started := time.Now().UTC().Format(time.RFC3339Nano)
			out, code := controlPlaneCommand(t, node, raw, "create", "--dry-run=server", "-f", "-", "-o", "json")
			got := classifyAdmission(code, string(out))
			observations = append(observations, trustObservation{phase, node, started, expected, got, string(out)})
			if got == expected {
				return
			}
			if got == "allowed" || (got != "unavailable" && got != "freshness-denied") || time.Now().After(deadline) {
				t.Fatalf("%s %s expected %s got %s: %s", phase, node, expected, got, out)
			}
			time.Sleep(time.Second)
		}
	}
	for _, node := range nodes {
		out, code := controlPlaneCommand(t, node, nil, "get", "--raw=/readyz")
		if code != 0 || string(out) != "ok" {
			t.Fatalf("API positive control %s: %s", node, out)
		}
		probe("all-apis-ready", node, inputs.SignedImage, "allowed")
		probe("all-apis-ready", node, inputs.UnsignedImage, "signature-denied")
	}
	// Suspend a complete control-plane node, including its API and etcd member.
	// The remaining two members retain quorum. Cleanup always resumes this node.
	paused := nodes[2]
	docker := func(action string) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", action, paused).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", action, err, out)
		}
	}
	docker("pause")
	resumed := false
	t.Cleanup(func() {
		if !resumed {
			docker("unpause")
		}
	})
	for _, node := range nodes[:2] {
		probe("one-control-plane-paused", node, inputs.SignedImage, "allowed")
		probe("one-control-plane-paused", node, inputs.UnsignedImage, "signature-denied")
	}
	docker("unpause")
	resumed = true
	for _, node := range nodes {
		probe("all-apis-restored", node, inputs.SignedImage, "allowed")
		probe("all-apis-restored", node, inputs.UnsignedImage, "signature-denied")
	}
	outcome = "passed"
	t.Log(fmt.Sprintf("PASS %d multi-control-plane observations on 3 explicit API endpoints", len(observations)))
}
