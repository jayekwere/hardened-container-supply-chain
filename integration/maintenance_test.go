//go:build admission

package integration

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMaintenance(t *testing.T) {
	nodes := admissionControlPlanes(t)
	var inputs admissionInputs
	b, err := os.ReadFile("../integration/admission/inputs.lock.json")
	if err != nil || json.Unmarshal(b, &inputs) != nil {
		t.Fatal("admission inputs unavailable")
	}
	observations := []trustObservation{}
	acknowledged := ""
	outcome := "failed"
	encode := func(object any) []byte { raw, _ := json.Marshal(object); return raw }
	must := func(input []byte, args ...string) []byte {
		out, code := controlPlaneCommand(t, nodes[0], input, args...)
		if code != 0 {
			t.Fatalf("maintenance setup %v: %s", args, out)
		}
		return out
	}
	label := "supply-chain.example.invalid/maintenance"
	t.Cleanup(func() {
		// These are only disposable test fixtures, never an operator's cluster.
		_, _ = controlPlaneCommand(t, nodes[0], nil, "label", "namespace", "signature-demo", label+"-")
		_, _ = controlPlaneCommand(t, nodes[0], nil, "-n", "signature-demo", "delete", "pod,deployments", "maintenance-probe", "--ignore-not-found", "--wait=false")
		raw := encode(map[string]any{"schemaVersion": 1, "outcome": outcome, "gateConfirmedOnAllAPIsAtUTC": acknowledged, "observations": observations})
		if err := os.WriteFile("../artifacts/admission/maintenance.json", append(raw, '\n'), 0600); err != nil {
			t.Error(err)
		}
	})
	security := map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}}
	spec := map[string]any{"automountServiceAccountToken": false, "schedulingGates": []any{map[string]string{"name": "hsc.test/admission-only"}}, "securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "seccompProfile": map[string]string{"type": "RuntimeDefault"}}, "containers": []any{map[string]any{"name": "service", "image": inputs.SignedImage, "securityContext": security}}}
	metadata := map[string]any{"name": "maintenance-probe", "namespace": "signature-demo", "labels": map[string]string{"app": "maintenance-probe"}}
	template := map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": "maintenance-probe"}}, "spec": spec}
	selector := map[string]any{"matchLabels": map[string]string{"app": "maintenance-probe"}}
	objects := []map[string]any{{"apiVersion": "v1", "kind": "Pod", "metadata": metadata, "spec": spec}}
	for _, kind := range []string{"Deployment", "ReplicaSet", "StatefulSet", "DaemonSet"} {
		workloadSpec := map[string]any{"selector": selector, "template": template}
		if kind != "DaemonSet" {
			workloadSpec["replicas"] = 0
		}
		if kind == "StatefulSet" {
			workloadSpec["serviceName"] = "maintenance-probe"
		}
		objects = append(objects, map[string]any{"apiVersion": "apps/v1", "kind": kind, "metadata": metadata, "spec": workloadSpec})
	}
	objects = append(objects, map[string]any{"apiVersion": "v1", "kind": "ReplicationController", "metadata": metadata, "spec": map[string]any{"replicas": 0, "selector": map[string]string{"app": "maintenance-probe"}, "template": template}})
	// Jobs need a different restart policy, so clone the template before editing.
	var jobTemplate map[string]any
	_ = json.Unmarshal(encode(template), &jobTemplate)
	jobTemplate["spec"].(map[string]any)["restartPolicy"] = "Never"
	jobSpec := map[string]any{"template": jobTemplate}
	objects = append(objects, map[string]any{"apiVersion": "batch/v1", "kind": "Job", "metadata": metadata, "spec": jobSpec})
	objects = append(objects, map[string]any{"apiVersion": "batch/v1", "kind": "CronJob", "metadata": metadata, "spec": map[string]any{"schedule": "0 0 * * *", "suspend": true, "jobTemplate": map[string]any{"spec": jobSpec}}})
	record := func(phase, node, expected string, input []byte, args ...string) {
		at := time.Now().UTC().Format(time.RFC3339Nano)
		out, code := controlPlaneCommand(t, node, input, args...)
		got := "other"
		if code == 0 {
			got = "allowed"
		} else if strings.Contains(string(out), "HSC-MAINTENANCE:") && strings.Contains(string(out), "hsc-maintenance") {
			got = "maintenance-denied"
		} else {
			got = classifyAdmission(code, string(out))
		}
		observations = append(observations, trustObservation{phase, node, at, expected, got, string(out)})
		if got != expected {
			t.Fatalf("maintenance %s on %s expected %s got %s: %s", phase, node, expected, got, out)
		}
	}
	// Establish that each object is valid before a gate denial can count.
	for _, object := range objects {
		record("open-create-"+object["kind"].(string), nodes[0], "allowed", encode(object), "create", "--dry-run=server", "-f", "-", "-o", "json")
	}
	must(encode(objects[0]), "create", "-f", "-")
	must(encode(objects[1]), "create", "-f", "-")
	must(nil, "label", "namespace", "signature-demo", label+"=locked", "--overwrite")
	var gateObject map[string]any
	_ = json.Unmarshal(encode(objects[0]), &gateObject)
	gateObject["metadata"].(map[string]any)["name"] = "maintenance-gate-propagation"
	// Namespace-label propagation is asynchronous. No policy change occurs until
	// the actual deny is observed separately on every API server.
	for _, node := range nodes {
		deadline := time.Now().Add(30 * time.Second)
		for {
			at := time.Now().UTC().Format(time.RFC3339Nano)
			out, code := controlPlaneCommand(t, node, encode(gateObject), "create", "--dry-run=server", "-f", "-", "-o", "json")
			got := classifyAdmission(code, string(out))
			if code != 0 && strings.Contains(string(out), "HSC-MAINTENANCE:") && strings.Contains(string(out), "hsc-maintenance") {
				got = "maintenance-denied"
			}
			observations = append(observations, trustObservation{"gate-propagation", node, at, "eventually-maintenance-denied", got, string(out)})
			if got == "maintenance-denied" {
				break
			}
			if time.Now().After(deadline) || got != "allowed" {
				t.Fatalf("gate positive control on %s: %s", node, out)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	acknowledged = time.Now().UTC().Format(time.RFC3339Nano)
	for _, node := range nodes {
		for _, original := range objects {
			var object map[string]any
			_ = json.Unmarshal(encode(original), &object)
			object["metadata"].(map[string]any)["name"] = "locked-create-probe"
			record("locked-create-"+object["kind"].(string), node, "maintenance-denied", encode(object), "create", "--dry-run=server", "-f", "-", "-o", "json")
		}
		for _, resource := range []string{"pod", "deployment"} {
			record("locked-update-"+resource, node, "maintenance-denied", nil, "-n", "signature-demo", "patch", resource, "maintenance-probe", "--type=merge", "-p", `{"metadata":{"annotations":{"probe":"changed"}}}`, "--dry-run=server", "-o", "json")
		}
		record("locked-scale", node, "maintenance-denied", nil, "-n", "signature-demo", "scale", "deployment/maintenance-probe", "--replicas=1", "--dry-run=server", "-o", "json")
		ephemeral := map[string]any{"spec": map[string]any{"ephemeralContainers": []any{map[string]any{"name": "debug", "image": inputs.SignedImage, "securityContext": security}}}}
		record("locked-ephemeral-container", node, "maintenance-denied", nil, "-n", "signature-demo", "patch", "pod", "maintenance-probe", "--subresource=ephemeralcontainers", "--type=merge", "-p", string(encode(ephemeral)), "--dry-run=server", "-o", "json")
		record("locked-status-cleanup", node, "allowed", nil, "-n", "signature-demo", "patch", "pod", "maintenance-probe", "--subresource=status", "--type=merge", "-p", `{"status":{"phase":"Pending"}}`, "--dry-run=server", "-o", "json")
		record("locked-delete-cleanup", node, "allowed", nil, "-n", "signature-demo", "delete", "pod", "maintenance-probe", "--dry-run=server", "-o", "name")
		record("locked-policy-administration", node, "allowed", nil, "annotate", "clusterimagepolicy", "release-signer", "supply-chain.example.invalid/maintenance-probe=checked", "--overwrite", "--dry-run=server", "-o", "json")
		var outside map[string]any
		_ = json.Unmarshal(encode(objects[0]), &outside)
		outside["metadata"].(map[string]any)["namespace"] = "signature-outside"
		outside["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"] = inputs.UnsignedImage
		record("outside-namespace", node, "allowed", encode(outside), "create", "--dry-run=server", "-f", "-", "-o", "json")
	}
	// Make a real harmless policy-metadata write while workload admission is shut.
	must(nil, "annotate", "clusterimagepolicy", "release-signer", "supply-chain.example.invalid/maintenance-probe=checked", "--overwrite")
	must(nil, "label", "namespace", "signature-demo", label+"-")
	for _, node := range nodes {
		var object map[string]any
		_ = json.Unmarshal(encode(objects[0]), &object)
		object["metadata"].(map[string]any)["name"] = "restored-maintenance-probe"
		record("restored-valid", node, "allowed", encode(object), "create", "--dry-run=server", "-f", "-", "-o", "json")
		object["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"] = inputs.UnsignedImage
		record("restored-unsigned", node, "signature-denied", encode(object), "create", "--dry-run=server", "-f", "-", "-o", "json")
	}
	outcome = "passed"
	t.Logf("PASS maintenance gate: %d observations across three API servers", len(observations))
}
