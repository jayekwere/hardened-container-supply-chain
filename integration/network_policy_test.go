//go:build kubernetes

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type networkPod struct {
	Namespace, Name, UID, Node, IP string
	PID                            int
}
type probeResult struct {
	ExpectedIP string `json:"expectedIP"`
	Reachable  bool   `json:"reachable"`
	Outcome    string `json:"outcome"`
	Detail     string `json:"detail,omitempty"`
}
type trafficFlow struct {
	Name             string
	From             networkPod
	Protocol, Target string
	Allowed          bool
}
type observation struct {
	Phase, Flow, SourcePod, SourceNode, Target, Protocol string
	Attempt, ExitCode                                    int
	ExpectedAllowed                                      bool
	Result                                               probeResult
}
type networkEvidence struct {
	SchemaVersion                                 int
	StartedAt, FinishedAt, Outcome, EnforcerImage string
	Pods                                          []networkPod
	Observations                                  []observation
}

func TestNetworkPolicyTraffic(t *testing.T) {
	config, name := os.Getenv("TEST_KUBECONFIG"), os.Getenv("TEST_KIND_NAME")
	if config == "" || !strings.HasPrefix(name, "hsc-") {
		t.Fatal("explicit isolated TEST_KUBECONFIG and TEST_KIND_NAME required")
	}
	root := ".."
	evidence := networkEvidence{SchemaVersion: 1, StartedAt: time.Now().UTC().Format(time.RFC3339), Outcome: "failed"}
	t.Cleanup(func() {
		evidence.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		raw, _ := json.MarshalIndent(evidence, "", "  ")
		if err := os.WriteFile(filepath.Join(root, "artifacts/cluster/network-policy.json"), append(raw, '\n'), 0600); err != nil {
			t.Error(err)
		}
	})
	kube := func(input []byte, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", config}, args...)...)
		if input != nil {
			cmd.Stdin = strings.NewReader(string(input))
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("kubectl %v: %v %s", args, err, out)
		}
		return out
	}
	docker := func(node string, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", append([]string{"exec", node}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("node command %v: %v %s", args, err, out)
		}
		return out
	}
	var lock struct{ Image string }
	raw, err := os.ReadFile(filepath.Join(root, "integration/network-policy/enforcer.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	evidence.EnforcerImage = lock.Image
	var agent struct {
		Spec struct {
			Template struct {
				Spec struct{ Containers []struct{ Image string } }
			}
		}
		Status struct{ DesiredNumberScheduled, NumberReady int }
	}
	if err := json.Unmarshal(kube(nil, "-n", "kube-system", "get", "daemonset", "kube-network-policies", "-o", "json"), &agent); err != nil {
		t.Fatal(err)
	}
	if agent.Status.DesiredNumberScheduled != 2 || agent.Status.NumberReady != 2 || len(agent.Spec.Template.Spec.Containers) != 1 || agent.Spec.Template.Spec.Containers[0].Image != lock.Image {
		t.Fatal("expected pinned policy agent ready on both nodes")
	}
	getPod := func(namespace, pod string) networkPod {
		t.Helper()
		var p struct {
			Metadata struct{ Name, UID string }
			Spec     struct{ NodeName string }
			Status   struct {
				PodIP, Phase      string
				ContainerStatuses []struct {
					Ready        bool
					RestartCount int
				}
			}
		}
		if err := json.Unmarshal(kube(nil, "-n", namespace, "get", "pod", pod, "-o", "json"), &p); err != nil {
			t.Fatal(err)
		}
		if p.Status.Phase != "Running" || p.Status.PodIP == "" || len(p.Status.ContainerStatuses) != 1 || !p.Status.ContainerStatuses[0].Ready || p.Status.ContainerStatuses[0].RestartCount != 0 {
			t.Fatalf("unhealthy test pod: %s/%s", namespace, pod)
		}
		np := networkPod{Namespace: namespace, Name: p.Metadata.Name, UID: p.Metadata.UID, Node: p.Spec.NodeName, IP: p.Status.PodIP}
		var sandboxes struct {
			Items []struct {
				ID       string
				Metadata struct{ UID string }
			}
		}
		if err := json.Unmarshal(docker(np.Node, "crictl", "pods", "-o", "json"), &sandboxes); err != nil {
			t.Fatal(err)
		}
		for _, sandbox := range sandboxes.Items {
			if sandbox.Metadata.UID == np.UID {
				var inspect struct{ Info struct{ PID int } }
				if err := json.Unmarshal(docker(np.Node, "crictl", "inspectp", sandbox.ID), &inspect); err != nil {
					t.Fatal(err)
				}
				np.PID = inspect.Info.PID
			}
		}
		if np.PID <= 0 {
			t.Fatal("pod sandbox PID not found")
		}
		return np
	}
	var pods struct {
		Items []struct {
			Metadata struct{ Name string }
			Spec     struct{ Containers []struct{ Image string } }
		}
	}
	if err := json.Unmarshal(kube(nil, "-n", "supply-demo", "get", "pods", "-l", "app.kubernetes.io/instance=demo", "-o", "json"), &pods); err != nil {
		t.Fatal(err)
	}
	if len(pods.Items) != 1 || len(pods.Items[0].Spec.Containers) != 1 {
		t.Fatal("expected one deployed workload")
	}
	image := pods.Items[0].Spec.Containers[0].Image
	app := getPod("supply-demo", pods.Items[0].Metadata.Name)
	if app.Node != name+"-worker" {
		t.Fatal("workload must be on worker for explicit topology")
	}
	kube(nil, "create", "namespace", "supply-demo-peer")
	kube(nil, "label", "namespace", "supply-demo-peer", "pod-security.kubernetes.io/enforce=restricted", "pod-security.kubernetes.io/enforce-version=v1.34")
	for _, fixture := range []struct{ Namespace, Name, Node string }{{"supply-demo", "netpol-local", name + "-control-plane"}, {"supply-demo-peer", "netpol-other", name + "-worker"}} {
		pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": fixture.Name, "namespace": fixture.Namespace, "labels": map[string]string{"hsc.fixture": "network-peer"}}, "spec": map[string]any{
			"nodeName": fixture.Node, "automountServiceAccountToken": false,
			"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": map[string]string{"type": "RuntimeDefault"}},
			"containers":      []any{map[string]any{"name": "peer", "image": image, "imagePullPolicy": "Never", "readinessProbe": map[string]any{"httpGet": map[string]any{"path": "/healthz", "port": 8080}, "periodSeconds": 1}, "securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}}, "resources": map[string]any{"requests": map[string]string{"cpu": "10m", "memory": "16Mi"}, "limits": map[string]string{"cpu": "100m", "memory": "32Mi"}}}},
		}}
		raw, _ := json.Marshal(pod)
		kube(raw, "create", "-f", "-")
		kube(nil, "-n", fixture.Namespace, "wait", "--for=condition=Ready", "pod/"+fixture.Name, "--timeout=15s")
	}
	local, other := getPod("supply-demo", "netpol-local"), getPod("supply-demo-peer", "netpol-other")
	evidence.Pods = []networkPod{app, local, other}
	serviceIP := func(namespace, name string) string {
		var s struct{ Spec struct{ ClusterIP string } }
		if err := json.Unmarshal(kube(nil, "-n", namespace, "get", "service", name, "-o", "json"), &s); err != nil {
			t.Fatal(err)
		}
		return s.Spec.ClusterIP
	}
	svc, dns := serviceIP("supply-demo", "demo"), serviceIP("kube-system", "kube-dns")
	httpURL := func(ip string) string { return "http://" + ip + ":8080/healthz" }
	flows := []trafficFlow{
		{"same-namespace-to-pod", local, "http", httpURL(app.IP), true},
		{"same-namespace-to-service", local, "http", httpURL(svc), true},
		{"cross-namespace-to-pod", other, "http", httpURL(app.IP), false},
		{"cross-namespace-to-service", other, "http", httpURL(svc), false},
		{"workload-to-same-namespace-peer", app, "http", httpURL(local.IP), false},
		{"workload-to-other-namespace-peer", app, "http", httpURL(other.IP), false},
		{"workload-to-dns-udp53", app, "dns", dns, false},
		{"unselected-peer-to-other-peer", local, "http", httpURL(other.IP), true},
		{"unselected-peer-to-dns", local, "dns", dns, true},
		{"unselected-other-to-local-peer", other, "http", httpURL(local.IP), true},
	}
	var snapshot struct{ Spec json.RawMessage }
	if err := json.Unmarshal(kube(nil, "-n", "supply-demo", "get", "networkpolicy", "demo", "-o", "json"), &snapshot); err != nil {
		t.Fatal(err)
	}
	policy, _ := json.Marshal(map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": map[string]string{"name": "demo", "namespace": "supply-demo"}, "spec": snapshot.Spec})
	// Restore the exact chart policy even if a phase fails; the outer script removes the cluster.
	t.Cleanup(func() {
		cmd := exec.Command("kubectl", "--kubeconfig", config, "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(string(policy))
		_ = cmd.Run()
	})
	phase := func(t *testing.T, label string, enforced bool, rounds int) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		consecutive, attempt := 0, 0
		for consecutive < rounds {
			attempt++
			all := true
			for _, flow := range flows {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				cmd := exec.CommandContext(ctx, "docker", "exec", flow.From.Node, "nsenter", "--target", fmt.Sprint(flow.From.PID), "--net", "/hsc-netprobe", flow.From.IP, flow.Protocol, flow.Target)
				out, err := cmd.Output()
				cancel()
				exit := 0
				if err != nil {
					var ex *exec.ExitError
					if !errors.As(err, &ex) {
						t.Fatalf("probe execution: %v", err)
					}
					exit = ex.ExitCode()
				}
				var result probeResult
				if err := json.Unmarshal(out, &result); err != nil {
					t.Fatalf("invalid probe output (exit %d): %v %s", exit, err, out)
				}
				allowed := !enforced || flow.Allowed
				evidence.Observations = append(evidence.Observations, observation{Phase: label, Flow: flow.Name, SourcePod: flow.From.Namespace + "/" + flow.From.Name, SourceNode: flow.From.Node, Target: flow.Target, Protocol: flow.Protocol, Attempt: attempt, ExitCode: exit, ExpectedAllowed: allowed, Result: result})
				if !probeMatches(result, exit, flow.From.IP, allowed) {
					all = false
				}
				if exit != 0 && exit != 10 {
					t.Fatalf("probe infrastructure/application error, never a policy denial: exit=%d %+v", exit, result)
				}
			}
			if all {
				consecutive++
			} else {
				consecutive = 0
			}
			if consecutive < rounds {
				if time.Now().After(deadline) {
					t.Fatalf("%s did not converge; inspect network-policy.json", label)
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
		for _, flow := range flows {
			want := "reachable"
			if enforced && !flow.Allowed {
				want = "timeout"
			}
			t.Logf("%s %s: %s (%d consecutive rounds)", label, flow.Name, want, rounds)
		}
	}
	kube(nil, "-n", "supply-demo", "delete", "networkpolicy", "demo")
	if !t.Run("baseline-policy-absent", func(t *testing.T) { phase(t, "baseline", false, 1) }) {
		t.Fatal("baseline failed")
	}
	kube(policy, "apply", "-f", "-")
	if !t.Run("policy-enforced", func(t *testing.T) { phase(t, "enforced", true, 3) }) {
		t.Fatal("enforcement failed")
	}
	kube(nil, "-n", "supply-demo", "delete", "networkpolicy", "demo")
	if !t.Run("policy-removal-restores-traffic", func(t *testing.T) { phase(t, "restored", false, 1) }) {
		t.Fatal("restoration failed")
	}
	kube(policy, "apply", "-f", "-")
	if !t.Run("policy-reapply-enforces-again", func(t *testing.T) { phase(t, "reapplied", true, 3) }) {
		t.Fatal("reapplication failed")
	}
	evidence.Outcome = "passed"
}

func probeMatches(r probeResult, exit int, expectedIP string, allowed bool) bool {
	if r.ExpectedIP != expectedIP {
		return false
	}
	if allowed {
		return exit == 0 && r.Reachable && r.Outcome == "reachable"
	}
	return exit == 10 && !r.Reachable && r.Outcome == "timeout"
}
