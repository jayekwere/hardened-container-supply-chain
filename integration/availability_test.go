//go:build admission

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type etcdMember struct {
	Node   string `json:"node"`
	Member uint64 `json:"memberID"`
	Leader uint64 `json:"leaderID"`
	Term   uint64 `json:"term"`
}

// Runtime inspection stays inside named disposable nodes. Certificates never
// leave the etcd container, and no API proxy can select another member.
func localEtcdStatus(t *testing.T, node string) etcdMember {
	t.Helper()
	allowed := false
	for _, n := range admissionControlPlanes(t) {
		allowed = allowed || n == node
	}
	if !allowed {
		t.Fatal("unexpected etcd node")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id, err := exec.CommandContext(ctx, "docker", "exec", node, "crictl", "ps", "--name", "etcd", "-q").Output()
	if err != nil || len(strings.Fields(string(id))) != 1 {
		t.Fatalf("etcd runtime positive control on %s: %v", node, err)
	}
	out, err := exec.CommandContext(ctx, "docker", "exec", node, "crictl", "exec", strings.TrimSpace(string(id)), "etcdctl", "--endpoints=https://127.0.0.1:2379", "--cacert=/etc/kubernetes/pki/etcd/ca.crt", "--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt", "--key=/etc/kubernetes/pki/etcd/healthcheck-client.key", "--command-timeout=5s", "endpoint", "status", "--write-out=json").CombinedOutput()
	if err != nil {
		t.Fatalf("etcd status on %s: %v %s", node, err, out)
	}
	var result []struct {
		Status struct {
			Header struct {
				Member uint64 `json:"member_id"`
			}
			Leader uint64 `json:"leader"`
			Term   uint64 `json:"raftTerm"`
		}
	}
	if json.Unmarshal(out, &result) != nil || len(result) != 1 || result[0].Status.Header.Member == 0 {
		t.Fatalf("invalid etcd status: %s", out)
	}
	s := result[0].Status
	return etcdMember{node, s.Header.Member, s.Leader, s.Term}
}

func TestAvailability(t *testing.T) {
	nodes := admissionControlPlanes(t)
	var inputs admissionInputs
	b, err := os.ReadFile("../integration/admission/inputs.lock.json")
	if err != nil || json.Unmarshal(b, &inputs) != nil {
		t.Fatal("admission inputs unavailable")
	}
	started := time.Now().UTC().Format(time.RFC3339Nano)
	observations := []trustObservation{}
	members := map[string][]etcdMember{}
	paused := map[string]bool{}
	placement := map[string]string{}
	configurations := map[string]json.RawMessage{}
	outcome := "failed"
	nodeAction := func(action, node string) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", action, node).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v %s", action, node, err, out)
		}
		paused[node] = action == "pause"
	}
	t.Cleanup(func() {
		for _, node := range nodes {
			if paused[node] {
				nodeAction("unpause", node)
			}
		}
		record := map[string]any{"schemaVersion": 1, "outcome": outcome, "startedAtUTC": started, "finishedAtUTC": time.Now().UTC().Format(time.RFC3339Nano), "verifierPlacement": placement, "effectiveConfiguration": configurations, "etcdMembers": members, "observations": observations}
		raw, _ := json.MarshalIndent(record, "", "  ")
		if err := os.WriteFile("../artifacts/admission/availability.json", append(raw, '\n'), 0600); err != nil {
			t.Error(err)
		}
	})
	pod := func(image string) []byte {
		object := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "availability-probe", "namespace": "signature-demo"}, "spec": map[string]any{"automountServiceAccountToken": false, "schedulingGates": []any{map[string]string{"name": "hsc.test/admission-only"}}, "securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "seccompProfile": map[string]string{"type": "RuntimeDefault"}}, "containers": []any{map[string]any{"name": "service", "image": image, "securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}}}}}}
		raw, _ := json.Marshal(object)
		return raw
	}
	probe := func(phase, node, image, expected string) {
		deadline := time.Now().Add(90 * time.Second)
		for {
			at := time.Now().UTC().Format(time.RFC3339Nano)
			out, code := controlPlaneCommand(t, node, pod(image), "create", "--dry-run=server", "-f", "-", "-o", "json")
			got := classifyAdmission(code, string(out))
			if got == "other" && code != 0 && quorumFailure(string(out)) {
				got = "api-unavailable"
			}
			observations = append(observations, trustObservation{phase, node, at, expected, got, string(out)})
			if got == expected {
				return
			}
			if got == "allowed" || (got != "unavailable" && got != "freshness-denied" && got != "api-unavailable") || time.Now().After(deadline) {
				t.Fatalf("%s on %s expected %s got %s: %s", phase, node, expected, got, out)
			}
			time.Sleep(time.Second)
		}
	}
	check := func(phase string, targets []string) {
		for _, node := range targets {
			probe(phase, node, inputs.SignedImage, "allowed")
			probe(phase, node, inputs.UnsignedImage, "signature-denied")
		}
	}
	ready := func() {
		for _, node := range nodes {
			deadline := time.Now().Add(60 * time.Second)
			for {
				out, code := controlPlaneCommand(t, node, nil, "get", "--raw=/readyz")
				if code == 0 && strings.TrimSpace(string(out)) == "ok" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("API did not recover on %s: %s", node, out)
				}
				time.Sleep(time.Second)
			}
		}
	}
	ready()
	for _, resource := range []string{"deployment", "poddisruptionbudget"} {
		raw, code := controlPlaneCommand(t, nodes[0], nil, "-n", "image-policy-system", "get", resource, "policy-controller-webhook", "-o", "json")
		if code != 0 || !json.Valid(raw) {
			t.Fatalf("effective %s configuration: %s", resource, raw)
		}
		configurations[resource] = raw
	}
	var deployment struct {
		Spec struct {
			Replicas int
			Strategy struct {
				RollingUpdate struct{ MaxUnavailable, MaxSurge int }
			}
		}
	}
	var budget struct{ Spec struct{ MinAvailable int } }
	if json.Unmarshal(configurations["deployment"], &deployment) != nil || json.Unmarshal(configurations["poddisruptionbudget"], &budget) != nil || deployment.Spec.Replicas != 2 || deployment.Spec.Strategy.RollingUpdate.MaxUnavailable != 1 || deployment.Spec.Strategy.RollingUpdate.MaxSurge != 0 || budget.Spec.MinAvailable != 1 {
		t.Fatal("effective replica, rollout or disruption settings differ from the checked profile")
	}
	out, code := controlPlaneCommand(t, nodes[0], nil, "-n", "image-policy-system", "get", "pods", "-l", "app.kubernetes.io/instance=policy-controller", "-o", "json")
	var pods struct {
		Items []struct {
			Metadata struct{ Name, DeletionTimestamp string }
			Spec     struct{ NodeName string }
			Status   struct {
				Conditions []struct{ Type, Status string }
			}
		}
	}
	if code != 0 || json.Unmarshal(out, &pods) != nil {
		t.Fatalf("placement: %s", out)
	}
	for _, p := range pods.Items {
		if p.Metadata.DeletionTimestamp == "" {
			for _, c := range p.Status.Conditions {
				if c.Type == "Ready" && c.Status == "True" {
					placement[p.Metadata.Name] = p.Spec.NodeName
				}
			}
		}
	}
	used := map[string]bool{}
	for _, node := range placement {
		used[node] = true
	}
	if len(placement) != 2 || len(used) != 2 || used[nodes[2]] {
		t.Fatalf("two ready verifiers must occupy separate non-reserved nodes: %v", placement)
	}
	check("baseline", nodes)

	// A complete verifier-hosting node fails, including its API and etcd member.
	nodeAction("pause", nodes[0])
	check("verifier-node-paused", nodes[1:])
	nodeAction("unpause", nodes[0])
	ready()
	check("verifier-node-restored", nodes)

	for _, node := range nodes {
		members["before-leader-loss"] = append(members["before-leader-loss"], localEtcdStatus(t, node))
	}
	previous := members["before-leader-loss"][0].Leader
	leaderNode := ""
	for _, m := range members["before-leader-loss"] {
		if m.Leader != previous || previous == 0 {
			t.Fatal("etcd members disagree before leader-loss experiment")
		}
		if m.Member == previous {
			leaderNode = m.Node
		}
	}
	if leaderNode == "" {
		t.Fatal("leader not mapped to a disposable node")
	}
	nodeAction("pause", leaderNode)
	survivors := []string{}
	for _, node := range nodes {
		if node != leaderNode {
			survivors = append(survivors, node)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		m := localEtcdStatus(t, survivors[0])
		if m.Leader != 0 && m.Leader != previous {
			members["after-leader-loss"] = []etcdMember{m, localEtcdStatus(t, survivors[1])}
			if members["after-leader-loss"][1].Leader == m.Leader {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("surviving etcd members did not elect a different leader")
		}
		time.Sleep(time.Second)
	}
	check("elected-leader-paused", survivors)
	nodeAction("unpause", leaderNode)
	ready()
	check("leader-restored", nodes)

	// Keep a verifier and its API alive, but remove two of the three etcd voters.
	// Check an actual storage write before the admission dry-run; no cached read
	// or syntactically invalid request can substitute for quorum-loss evidence.
	nodeAction("pause", nodes[0])
	nodeAction("pause", nodes[2])
	at := time.Now().UTC().Format(time.RFC3339Nano)
	out, code = controlPlaneCommand(t, nodes[1], nil, "--request-timeout=12s", "-n", "signature-outside", "create", "configmap", "quorum-positive-control", "--from-literal=control=requires-storage")
	if code == 0 || !quorumFailure(string(out)) {
		t.Fatalf("quorum-loss storage control must fail with an availability error: %d %s", code, out)
	}
	observations = append(observations, trustObservation{"quorum-lost-storage", nodes[1], at, "storage-unavailable", "storage-unavailable", string(out)})
	at = time.Now().UTC().Format(time.RFC3339Nano)
	out, code = controlPlaneCommand(t, nodes[1], pod(inputs.SignedImage), "--request-timeout=15s", "create", "--dry-run=server", "-f", "-", "-o", "json")
	got := classifyAdmission(code, string(out))
	if code == 0 || (got != "freshness-denied" && got != "unavailable" && !quorumFailure(string(out))) {
		t.Fatalf("quorum loss must not admit a valid image: %d %s", code, out)
	}
	if got == "other" {
		got = "storage-unavailable"
	}
	observations = append(observations, trustObservation{"quorum-lost-admission", nodes[1], at, "rejected", got, string(out)})
	nodeAction("unpause", nodes[0])
	nodeAction("unpause", nodes[2])
	ready()
	check("quorum-restored", nodes)
	for _, node := range nodes {
		members["restored"] = append(members["restored"], localEtcdStatus(t, node))
	}
	for _, member := range members["restored"] {
		if member.Leader == 0 || member.Leader != members["restored"][0].Leader {
			t.Fatal("restored etcd members must agree on a nonzero leader")
		}
	}
	_, _ = controlPlaneCommand(t, nodes[1], nil, "-n", "signature-outside", "delete", "configmap", "quorum-positive-control", "--ignore-not-found")
	outcome = "passed"
	t.Logf("PASS availability controls: %d recorded requests; forced leader change %d to %d", len(observations), previous, members["after-leader-loss"][0].Leader)
}

func quorumFailure(out string) bool {
	text := strings.ToLower(out)
	for _, invalid := range []string{"unknown flag", "forbidden", "unauthorized", "notfound", "alreadyexists", "certificate"} {
		if strings.Contains(text, invalid) {
			return false
		}
	}
	return strings.Contains(text, "etcdserver: request timed out") || strings.Contains(text, "etcdserver: leader changed") || strings.Contains(text, "context deadline exceeded") || strings.Contains(text, "server was unable to return a response in the time allotted") || strings.Contains(text, "timed out waiting for the condition")
}

func TestQuorumFailureClassification(t *testing.T) {
	for i, tc := range []struct {
		text string
		want bool
	}{
		{"etcdserver: request timed out", true},
		{"context deadline exceeded", true},
		{"Error from server (Timeout): the server was unable to return a response in the time allotted", true},
		{"unknown flag: context deadline exceeded", false},
		{"Forbidden: context deadline exceeded", false},
		{"Unauthorized", false},
		{"certificate has expired: context deadline exceeded", false},
		{"AlreadyExists: timed out waiting for the condition", false},
		{"unrelated process error", false},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if quorumFailure(tc.text) != tc.want {
				t.Fatal(tc.text)
			}
		})
	}
}
