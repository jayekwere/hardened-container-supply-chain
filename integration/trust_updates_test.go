//go:build admission

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type trustObservation struct {
	Phase    string `json:"phase"`
	Endpoint string `json:"endpoint"`
	Started  string `json:"startedAtUTC"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Output   string `json:"output"`
}

func TestTrustUpdates(t *testing.T) {
	config, cluster := os.Getenv("TEST_ADMISSION_KUBECONFIG"), os.Getenv("TEST_ADMISSION_KIND_NAME")
	if config == "" || !strings.HasPrefix(cluster, "hsc-admission-") {
		t.Fatal("explicit disposable cluster required")
	}
	var inputs admissionInputs
	raw, err := os.ReadFile("../integration/admission/inputs.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &inputs); err != nil {
		t.Fatal(err)
	}
	observations := []trustObservation{}
	outcome := "failed"
	started := time.Now().UTC().Format(time.RFC3339Nano)
	acknowledgements := map[string]string{}
	var endpointPods []string
	policyWrites := []policyWriteAttempt{}
	authorizationChecks := []map[string]any{}
	compiledChecks := []map[string]string{}
	compiledInputs := map[string]map[string]string{}
	t.Cleanup(func() {
		d := map[string]any{"schemaVersion": 1, "startedAtUTC": started, "finishedAtUTC": time.Now().UTC().Format(time.RFC3339Nano), "outcome": outcome, "signedImage": inputs.SignedImage, "policyWriteAcknowledgements": acknowledgements, "policyWriteAttempts": policyWrites, "authorizationChecks": authorizationChecks, "compiledSnapshotInputs": compiledInputs, "compiledSnapshotChecks": compiledChecks, "endpointPods": endpointPods, "observations": observations}
		b, _ := json.MarshalIndent(d, "", "  ")
		if err := os.WriteFile("../artifacts/admission/trust-updates.json", append(b, '\n'), 0600); err != nil {
			t.Error(err)
		}
	})
	command := func(input []byte, args ...string) ([]byte, int) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", config, "--request-timeout=40s"}, args...)...)
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return out, 0
		}
		if e, ok := err.(*exec.ExitError); ok {
			return out, e.ExitCode()
		}
		t.Fatalf("kubectl: %v", err)
		return nil, -1
	}
	must := func(input []byte, args ...string) []byte {
		out, code, attempts := applyPolicyCommand(command, input, time.Sleep, args...)
		policyWrites = append(policyWrites, attempts...)
		if code != 0 {
			t.Fatalf("kubectl %v: %s", args, out)
		}
		return out
	}
	encode := func(v any) []byte {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	record := func(phase, endpoint, start, expected, observed, output string) {
		observations = append(observations, trustObservation{phase, endpoint, start, expected, observed, output})
		good := observed == expected
		if expected == "deny" {
			good = observed == "identity-denied" || observed == "freshness-denied" || observed == "extra-policy-denied" || observed == "unavailable" || observed == "draining-unavailable"
		}
		if !good {
			t.Fatalf("%s on %s expected %s got %s: %s", phase, endpoint, expected, observed, output)
		}
	}
	classify := func(code int, out string) string {
		got := classifyAdmission(code, out)
		if got == "other" && strings.Contains(out, `admission webhook "policy.sigstore.dev" denied the request`) && strings.Contains(out, "TRUST-UPDATE-EXTRA-DENY") {
			return "extra-policy-denied"
		}
		return got
	}
	pod := func(namespace, image string) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "trust-update-probe", "namespace": namespace}, "spec": map[string]any{
			"automountServiceAccountToken": false, "schedulingGates": []any{map[string]any{"name": "hsc.test/admission-only"}},
			"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": map[string]string{"type": "RuntimeDefault"}},
			"containers":      []any{map[string]any{"name": "service", "image": image, "securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}}}},
		}}
	}
	apiProbe := func(phase, expected, namespace, image string) {
		for _, node := range admissionControlPlanes(t) {
			start := time.Now().UTC().Format(time.RFC3339Nano)
			out, code := controlPlaneCommand(t, node, encode(pod(namespace, image)), "create", "--dry-run=server", "-f", "-", "-o", "json")
			record(phase, node, start, expected, classify(code, string(out)), string(out))
		}
	}
	objectProbe := func(phase, expected string, object any) {
		start := time.Now().UTC().Format(time.RFC3339Nano)
		out, code := command(encode(object), "replace", "--dry-run=server", "-f", "-", "-o", "json")
		record(phase, "api-server", start, expected, classify(code, string(out)), string(out))
	}
	patch := func(kind, name string, v any) {
		must(nil, "-n", "image-policy-system", "patch", kind, name, "--type=merge", "--patch", string(encode(v)))
	}
	var deployment struct {
		Spec struct {
			Template struct {
				Spec struct{ ServiceAccountName string }
			}
		}
	}
	if err := json.Unmarshal(must(nil, "-n", "image-policy-system", "get", "deployment", "policy-controller-webhook", "-o", "json"), &deployment); err != nil {
		t.Fatal(err)
	}
	account := "system:serviceaccount:image-policy-system:" + deployment.Spec.Template.Spec.ServiceAccountName
	if strings.HasSuffix(account, ":") {
		t.Fatal("missing verifier account")
	}
	readRules := func(kind string) any {
		var object map[string]any
		if err := json.Unmarshal(must(nil, "-n", "image-policy-system", "get", kind, "policy-controller-webhook", "-o", "json"), &object); err != nil {
			t.Fatal(err)
		}
		return object["rules"]
	}
	roleRules, clusterRules := readRules("role"), readRules("clusterrole")
	restoreWrites := func() { patch("role", "policy-controller-webhook", map[string]any{"rules": roleRules}) }
	restoreReads := func() { patch("clusterrole", "policy-controller-webhook", map[string]any{"rules": clusterRules}) }
	t.Cleanup(func() { restoreWrites(); restoreReads() })
	restrict := func(kind string, original any, resource string, remove map[string]bool) {
		var rules []map[string]any
		if err := json.Unmarshal(encode(original), &rules); err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			match := false
			for _, item := range r["resources"].([]any) {
				if item == resource {
					match = true
				}
			}
			if match {
				verbs := []any{}
				for _, v := range r["verbs"].([]any) {
					if !remove[v.(string)] {
						verbs = append(verbs, v)
					}
				}
				r["verbs"] = verbs
			}
		}
		patch(kind, "policy-controller-webhook", map[string]any{"rules": rules})
	}
	awaitAuthorization := func(verb, resource, want string) {
		for _, node := range admissionControlPlanes(t) {
			deadline := time.Now().Add(20 * time.Second)
			for {
				at := time.Now().UTC().Format(time.RFC3339Nano)
				out, code := controlPlaneCommand(t, node, nil, "auth", "can-i", verb, resource, "-n", "image-policy-system", "--as", account)
				words := strings.Fields(string(out))
				observed := "error"
				if len(words) > 0 {
					observed = words[len(words)-1]
				}
				authorizationChecks = append(authorizationChecks, map[string]any{"endpoint": node, "startedAtUTC": at, "verb": verb, "resource": resource, "expected": want, "observed": observed, "exitCode": code, "output": string(out)})
				if observed == want && ((want == "no" && code == 1) || (want == "yes" && code == 0)) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("permission positive control failed on %s: %d %s", node, code, out)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	awaitForbidden := func(verb, resource string) { awaitAuthorization(verb, resource, "no") }
	awaitPolicyDeleted := func(name string) {
		deadline := time.Now().Add(90 * time.Second)
		for {
			out, code := command(nil, "get", "clusterimagepolicy", name, "-o", "json")
			if code != 0 && strings.Contains(string(out), "NotFound") {
				return
			}
			if code != 0 || time.Now().After(deadline) {
				t.Fatalf("policy deletion did not recover: %s", out)
			}
			// The deliberately denied compiler writes cause reconciliation backoff.
			// A metadata event requeues cleanup after permissions are restored.
			out, code = command(nil, "annotate", "clusterimagepolicy", name, "hsc.test/recovery-trigger="+time.Now().UTC().Format(time.RFC3339Nano), "--overwrite")
			if code != 0 && !strings.Contains(string(out), "NotFound") {
				t.Fatalf("cannot requeue restored finalizer: %s", out)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	freezeWrites := func() {
		restrict("role", roleRules, "configmaps", map[string]bool{"create": true, "update": true, "patch": true, "delete": true})
		awaitForbidden("patch", "configmap/config-image-policies")
	}
	readCompiled := func() map[string]string {
		var value struct{ Data map[string]string }
		if err := json.Unmarshal(must(nil, "-n", "image-policy-system", "get", "configmap", "config-image-policies", "-o", "json"), &value); err != nil {
			t.Fatal(err)
		}
		return value.Data
	}
	checkCompiled := func(phase, input string) {
		expected := fmt.Sprintf("%x", sha256.Sum256(encode(compiledInputs[input])))
		observed := fmt.Sprintf("%x", sha256.Sum256(encode(readCompiled())))
		compiledChecks = append(compiledChecks, map[string]string{"phase": phase, "input": input, "checkedAtUTC": time.Now().UTC().Format(time.RFC3339Nano), "expectedSHA256": expected, "observedSHA256": observed})
		if expected != observed {
			t.Fatalf("compiled policy copy changed during frozen phase %s", phase)
		}
	}
	var hooks struct {
		Webhooks []struct{ ClientConfig struct{ CABundle []byte } }
	}
	if err := json.Unmarshal(must(nil, "get", "validatingwebhookconfiguration", "policy.sigstore.dev", "-o", "json"), &hooks); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if len(hooks.Webhooks) != 1 || !roots.AppendCertsFromPEM(hooks.Webhooks[0].ClientConfig.CABundle) {
		t.Fatal("invalid verifier CA")
	}
	type endpoint struct {
		name     string
		client   *http.Client
		url      string
		draining bool
	}
	connect := func(name string) *endpoint {
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", config, "-n", "image-policy-system", "port-forward", "--address=127.0.0.1", "pod/"+name, ":8443")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); _ = cmd.Wait() })
		address := make(chan string, 1)
		go func() {
			s := bufio.NewScanner(stdout)
			for s.Scan() {
				line := s.Text()
				if strings.HasPrefix(line, "Forwarding from 127.0.0.1:") {
					address <- strings.Fields(line)[2]
					return
				}
			}
		}()
		var host string
		select {
		case host = <-address:
		case <-time.After(20 * time.Second):
			t.Fatalf("port forward %s: %s", name, stderr.String())
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "webhook.image-policy-system.svc", MinVersion: tls.VersionTLS12}}
		t.Cleanup(transport.CloseIdleConnections)
		endpointPods = append(endpointPods, name)
		return &endpoint{name: name, client: &http.Client{Transport: transport, Timeout: 40 * time.Second}, url: "https://" + host + "/validations"}
	}
	directProbe := func(e *endpoint, phase, expected, image string) {
		start := time.Now().UTC().Format(time.RFC3339Nano)
		uid := fmt.Sprintf("trust-%d", len(observations))
		review := map[string]any{"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": map[string]any{"uid": uid, "kind": map[string]string{"group": "", "version": "v1", "kind": "Pod"}, "resource": map[string]string{"group": "", "version": "v1", "resource": "pods"}, "operation": "CREATE", "namespace": "signature-demo", "name": "trust-update-probe", "dryRun": true, "userInfo": map[string]any{"username": "trust-update-probe"}, "object": pod("signature-demo", image)}}
		response, err := e.client.Post(e.url, "application/json", bytes.NewReader(encode(review)))
		if err != nil {
			if e.draining && expected == "deny" {
				record(phase, e.name, start, expected, "draining-unavailable", err.Error())
				return
			}
			t.Fatalf("direct TLS probe %s: %v", e.name, err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Response *struct {
				UID     string
				Allowed *bool
				Status  struct{ Message string }
			}
		}
		if response.StatusCode != 200 || json.Unmarshal(body, &result) != nil || result.Response == nil || result.Response.UID != uid || result.Response.Allowed == nil {
			t.Fatalf("invalid verifier response: %s", body)
		}
		observed := "allowed"
		if !*result.Response.Allowed {
			observed = classify(1, `admission webhook "policy.sigstore.dev" denied the request: `+result.Response.Status.Message)
		}
		record(phase, e.name, start, expected, observed, string(body))
	}
	readyPods := func() []string {
		deadline := time.Now().Add(120 * time.Second)
		for {
			var pods struct {
				Items []struct {
					Metadata struct {
						Name              string
						DeletionTimestamp *string
					}
					Status struct {
						Conditions []struct{ Type, Status string }
					}
				}
			}
			if err := json.Unmarshal(must(nil, "-n", "image-policy-system", "get", "pods", "-l", "app.kubernetes.io/instance=policy-controller", "-o", "json"), &pods); err != nil {
				t.Fatal(err)
			}
			names := []string{}
			for _, p := range pods.Items {
				if p.Metadata.DeletionTimestamp == nil {
					for _, c := range p.Status.Conditions {
						if c.Type == "Ready" && c.Status == "True" {
							names = append(names, p.Metadata.Name)
						}
					}
				}
			}
			if len(names) == 2 {
				return names
			}
			if time.Now().After(deadline) {
				t.Fatal("two verifiers did not become ready")
			}
			time.Sleep(time.Second)
		}
	}
	must(nil, "-n", "image-policy-system", "scale", "deployment/policy-controller-webhook", "--replicas=2")
	t.Cleanup(func() {
		_, _ = command(nil, "-n", "image-policy-system", "scale", "deployment/policy-controller-webhook", "--replicas=2")
	})
	names := readyPods()
	endpoints := []*endpoint{connect(names[0]), connect(names[1])}
	for _, e := range endpoints {
		directProbe(e, "warm-cache", "allowed", inputs.SignedImage)
	}
	apiProbe("warm-cache", "allowed", "signature-demo", inputs.SignedImage)
	deploymentFixture := map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "trust-scale", "namespace": "signature-demo"}, "spec": map[string]any{"replicas": 2, "selector": map[string]any{"matchLabels": map[string]string{"app": "trust-scale"}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"app": "trust-scale"}}, "spec": pod("signature-demo", inputs.SignedImage)["spec"]}}}
	must(encode(deploymentFixture), "create", "-f", "-")
	freezeWrites()
	var cm struct{ Data map[string]string }
	if err := json.Unmarshal(must(nil, "-n", "image-policy-system", "get", "configmap", "config-image-policies", "-o", "json"), &cm); err != nil {
		t.Fatal(err)
	}
	for name, value := range cm.Data {
		if name == "_example" {
			continue
		}
		var p map[string]any
		if err := json.Unmarshal([]byte(value), &p); err != nil {
			t.Fatal(err)
		}
		p["authorities"] = []any{map[string]any{"name": "intentionally-unsafe-copy", "static": map[string]string{"action": "pass"}}}
		cm.Data[name] = string(encode(p))
	}
	patch("configmap", "config-image-policies", map[string]any{"data": cm.Data})
	compiledInputs["poisoned-copy"] = cm.Data
	checkCompiled("poisoned-before-probes", "poisoned-copy")
	for i := 0; i < 5; i++ {
		apiProbe("poisoned-compiled-copy", "signature-denied", "signature-demo", inputs.UnsignedImage)
		for _, e := range endpoints {
			directProbe(e, "poisoned-compiled-copy", "signature-denied", inputs.UnsignedImage)
		}
	}
	checkCompiled("poisoned-after-unsigned-probes", "poisoned-copy")
	apply := func(file string, change func(map[string]any), phase string) {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var p map[string]any
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		if change != nil {
			change(p)
		}
		must(encode(p), "apply", "-f", "-")
		acknowledgements[phase] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	wrongSubject := func(p map[string]any) {
		p["spec"].(map[string]any)["authorities"].([]any)[0].(map[string]any)["keyless"].(map[string]any)["identities"].([]any)[0].(map[string]any)["subject"] = strings.Replace(inputs.Subject, "release.yml", "unexpected.yml", 1)
	}
	must(nil, "-n", "image-policy-system", "delete", "pod", endpoints[0].name, "--wait=false")
	endpoints[0].draining = true
	// Exercise a real revision replacement while the warmed process drains.
	// Revision-scoped anti-affinity permits the replacement to start without
	// changing the retiring Pod's identity, scheduling rules or Service labels.
	patch("deployment", "policy-controller-webhook", map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{"annotations": map[string]string{"hsc.test/replacement": time.Now().UTC().Format(time.RFC3339Nano)}}}}})
	apply("../integration/admission/release-policy.json", wrongSubject, "signer-tightened")
	for _, variant := range []string{"replicas-only", "image-change", "label-change"} {
		var object map[string]any
		if err := json.Unmarshal(must(nil, "-n", "signature-demo", "get", "deployment", "trust-scale", "-o", "json"), &object); err != nil {
			t.Fatal(err)
		}
		object["spec"].(map[string]any)["replicas"] = 1
		expected := "allowed"
		if variant == "image-change" {
			object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"] = inputs.UnsignedImage
			expected = "signature-denied"
		}
		if variant == "label-change" {
			object["metadata"].(map[string]any)["labels"] = map[string]string{"changed": "true"}
			expected = "identity-denied"
		}
		objectProbe("scale-down-"+variant, expected, object)
	}
	for i := 0; i < 5; i++ {
		apiProbe("signer-tightened", "deny", "signature-demo", inputs.SignedImage)
		for _, e := range endpoints {
			directProbe(e, "signer-tightened", "deny", inputs.SignedImage)
		}
	}
	checkCompiled("signer-tightened", "poisoned-copy")
	apply("../integration/admission/release-policy.json", nil, "signer-restored")
	apply("../integration/admission/attestations-policy.json", wrongSubject, "attestation-tightened")
	names = readyPods()
	endpoints = []*endpoint{connect(names[0]), connect(names[1])}
	for i := 0; i < 5; i++ {
		apiProbe("attestation-tightened", "deny", "signature-demo", inputs.SignedImage)
		for _, e := range endpoints {
			directProbe(e, "attestation-tightened", "deny", inputs.SignedImage)
		}
	}
	checkCompiled("attestation-tightened", "poisoned-copy")
	restrict("clusterrole", clusterRules, "clusterimagepolicies", map[string]bool{"list": true})
	awaitForbidden("list", "clusterimagepolicies.policy.sigstore.dev")
	for i := 0; i < 5; i++ {
		apiProbe("authoritative-read-unavailable", "freshness-denied", "signature-demo", inputs.SignedImage)
		for _, e := range endpoints {
			directProbe(e, "authoritative-read-unavailable", "freshness-denied", inputs.SignedImage)
		}
	}
	checkCompiled("authoritative-read-unavailable", "poisoned-copy")
	apiProbe("outside-scope-read-outage", "allowed", "signature-outside", inputs.UnsignedImage)
	restoreReads()
	awaitAuthorization("list", "clusterimagepolicies.policy.sigstore.dev", "yes")
	apply("../integration/admission/attestations-policy.json", nil, "attestations-restored")
	for _, e := range endpoints {
		directProbe(e, "restored-with-poisoned-copy", "allowed", inputs.SignedImage)
	}
	checkCompiled("restored-with-poisoned-copy", "poisoned-copy")
	must(nil, "delete", "clusterimagepolicy", "release-attestations", "--wait=false")
	acknowledgements["mandatory-policy-deleted"] = time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < 5; i++ {
		apiProbe("mandatory-policy-deleted", "freshness-denied", "signature-demo", inputs.SignedImage)
		for _, e := range endpoints {
			directProbe(e, "mandatory-policy-deleted", "freshness-denied", inputs.SignedImage)
		}
	}
	checkCompiled("mandatory-policy-deleted", "poisoned-copy")
	restoreWrites()
	awaitAuthorization("patch", "configmap/config-image-policies", "yes")
	awaitPolicyDeleted("release-attestations")
	apply("../integration/admission/attestations-policy.json", nil, "mandatory-policy-recreated")
	apiProbe("mandatory-policy-recreated", "allowed", "signature-demo", inputs.SignedImage)
	freezeWrites()
	compiledInputs["before-extra-policy"] = readCompiled()
	extra := map[string]any{"apiVersion": "policy.sigstore.dev/v1beta1", "kind": "ClusterImagePolicy", "metadata": map[string]any{"name": "trust-update-extra"}, "spec": map[string]any{"images": []any{map[string]any{"glob": "ghcr.io/jayekwere/hardened-container-supply-chain@sha256:*"}}, "authorities": []any{map[string]any{"name": "deny", "static": map[string]string{"action": "fail", "message": "TRUST-UPDATE-EXTRA-DENY"}}}}}
	must(encode(extra), "apply", "-f", "-")
	acknowledgements["extra-policy-created"] = time.Now().UTC().Format(time.RFC3339Nano)
	for i := 0; i < 5; i++ {
		apiProbe("extra-policy-created", "deny", "signature-demo", inputs.SignedImage)
		for _, e := range endpoints {
			directProbe(e, "extra-policy-created", "deny", inputs.SignedImage)
		}
	}
	checkCompiled("extra-policy-created", "before-extra-policy")
	restoreWrites()
	awaitAuthorization("patch", "configmap/config-image-policies", "yes")
	must(nil, "delete", "clusterimagepolicy", "trust-update-extra", "--wait=false")
	awaitPolicyDeleted("trust-update-extra")
	for i := 0; i < 5; i++ {
		apiProbe("production-restored", "allowed", "signature-demo", inputs.SignedImage)
	}
	for _, e := range endpoints {
		directProbe(e, "production-restored", "allowed", inputs.SignedImage)
	}
	outcome = "passed"
	t.Logf("PASS %d trust-update probes; no stale allow accepted", len(observations))
}
