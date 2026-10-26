//go:build admission

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jayekwere/hardened-container-supply-chain/internal/policy"
)

type admissionInputs struct {
	SignedImage, UnsignedImage, Issuer, Subject string
	Controller                                  struct{ Image string }
}
type admissionAttempt struct {
	Case     string `json:"case"`
	Attempt  int    `json:"attempt"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	ExitCode int    `json:"exitCode"`
	Output   string `json:"output"`
}
type admissionEvidence struct {
	SchemaVersion   int                `json:"schemaVersion"`
	StartedAt       string             `json:"startedAtUTC"`
	FinishedAt      string             `json:"finishedAtUTC"`
	Outcome         string             `json:"outcome"`
	SignedImage     string             `json:"signedImage"`
	UnsignedImage   string             `json:"unsignedImage"`
	ControllerImage string             `json:"controllerImage"`
	Attempts        []admissionAttempt `json:"attempts"`
}

func TestAdmissionSignatures(t *testing.T) {
	config, name := os.Getenv("TEST_ADMISSION_KUBECONFIG"), os.Getenv("TEST_ADMISSION_KIND_NAME")
	if config == "" || !strings.HasPrefix(name, "hsc-admission-") {
		t.Fatal("explicit disposable admission cluster required")
	}
	var inputs admissionInputs
	raw, err := os.ReadFile("../integration/admission/inputs.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &inputs); err != nil {
		t.Fatal(err)
	}
	evidence := admissionEvidence{SchemaVersion: 1, StartedAt: time.Now().UTC().Format(time.RFC3339), Outcome: "failed", SignedImage: inputs.SignedImage, UnsignedImage: inputs.UnsignedImage, ControllerImage: inputs.Controller.Image}
	t.Cleanup(func() {
		evidence.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		raw, _ := json.MarshalIndent(evidence, "", "  ")
		if err := os.WriteFile("../artifacts/admission/decisions.json", append(raw, '\n'), 0600); err != nil {
			t.Error(err)
		}
	})
	command := func(input []byte, args ...string) ([]byte, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", config, "--request-timeout=40s"}, args...)...)
		if input != nil {
			cmd.Stdin = strings.NewReader(string(input))
		}
		out, err := cmd.CombinedOutput()
		if err == nil {
			return out, 0
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return out, exit.ExitCode()
		}
		t.Fatalf("kubectl invocation failed: %v", err)
		return nil, -1
	}
	must := func(input []byte, args ...string) []byte {
		t.Helper()
		out, code := command(input, args...)
		if code != 0 {
			t.Fatalf("kubectl %v exit %d: %s", args, code, out)
		}
		return out
	}
	for _, namespace := range []string{"signature-demo", "signature-outside"} {
		must(nil, "create", "namespace", namespace)
		must(nil, "label", "namespace", namespace, "pod-security.kubernetes.io/enforce=restricted", "pod-security.kubernetes.io/enforce-version=v1.34")
		must(nil, "-n", namespace, "wait", "--for=create", "serviceaccount/default", "--timeout=20s")
	}
	must(nil, "label", "namespace", "signature-demo", "policy.sigstore.dev/include=true")
	// Inspect the effective API-server webhooks, not only Helm values.
	for _, kind := range []string{"validatingwebhookconfiguration", "mutatingwebhookconfiguration"} {
		var config struct {
			Webhooks []struct {
				Name, FailurePolicy string
				ClientConfig        struct{ CABundle string }
				Rules               []struct{ Resources, Operations []string }
			}
		}
		if err := json.Unmarshal(must(nil, "get", kind, "policy.sigstore.dev", "-o", "json"), &config); err != nil {
			t.Fatal(err)
		}
		if len(config.Webhooks) != 1 || config.Webhooks[0].FailurePolicy != "Fail" || config.Webhooks[0].ClientConfig.CABundle == "" || len(config.Webhooks[0].Rules) == 0 {
			t.Fatalf("unready or fail-open webhook: %+v", config)
		}
	}
	var deployment struct {
		Spec struct {
			Template struct {
				Spec struct{ Containers []struct{ Image string } }
			}
		}
	}
	if err := json.Unmarshal(must(nil, "-n", "image-policy-system", "get", "deployment", "policy-controller-webhook", "-o", "json"), &deployment); err != nil {
		t.Fatal(err)
	}
	if len(deployment.Spec.Template.Spec.Containers) != 1 || deployment.Spec.Template.Spec.Containers[0].Image != inputs.Controller.Image {
		t.Fatal("controller image does not match lock")
	}
	security := map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}}
	container := func(name, image string) map[string]any {
		return map[string]any{"name": name, "image": image, "securityContext": security, "resources": map[string]any{"limits": map[string]string{"cpu": "100m", "memory": "32Mi"}}}
	}
	pod := func(name, namespace, image string) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name, "namespace": namespace}, "spec": map[string]any{
			"automountServiceAccountToken": false, "schedulingGates": []any{map[string]any{"name": "hsc.test/admission-only"}},
			"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532, "seccompProfile": map[string]string{"type": "RuntimeDefault"}}, "containers": []any{container("service", image)},
		}}
	}
	request := func(object any) []byte {
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	check := func(t *testing.T, caseName, expected string, input []byte, args ...string) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		for attempt := 1; ; attempt++ {
			out, code := command(input, args...)
			observed := classifyAdmission(code, string(out))
			evidence.Attempts = append(evidence.Attempts, admissionAttempt{Case: caseName, Attempt: attempt, Expected: expected, Observed: observed, ExitCode: code, Output: string(out)})
			if observed == expected {
				t.Logf("%s: %s (exit %d, attempt %d)", caseName, observed, code, attempt)
				return
			}
			if observed == "other" || (observed == "unavailable" && caseName != "verifier-restored") || time.Now().After(deadline) {
				t.Fatalf("%s expected %s, got %s (exit %d): %s", caseName, expected, observed, code, out)
			}
			time.Sleep(time.Second)
		}
	}
	run := func(name, expected string, object any, args ...string) {
		t.Helper()
		if !t.Run(name, func(t *testing.T) { check(t, name, expected, request(object), args...) }) {
			t.Fatal("admission case failed")
		}
	}
	create := []string{"create", "--dry-run=server", "-o", "json", "-f", "-"}
	base := pod("admitted-base", "signature-demo", inputs.SignedImage)
	run("signed-pod-persisted", "allowed", base, "create", "-o", "json", "-f", "-")
	var persisted map[string]any
	if err := json.Unmarshal(must(nil, "-n", "signature-demo", "get", "pod", "admitted-base", "-o", "json"), &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted["metadata"].(map[string]any)["uid"] == "" {
		t.Fatal("admitted Pod was not persisted")
	}
	// Use the real Helm Deployment as the workload-template admission control.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	digest := strings.SplitN(inputs.SignedImage, "@", 2)[1]
	rendered, err := exec.CommandContext(ctx, "helm", "template", "admitted-demo", "../charts/supply-demo", "--namespace", "signature-demo", "--set", "image.digest="+digest).Output()
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	docs, err := policy.DecodeManifests(rendered)
	if err != nil {
		t.Fatal(err)
	}
	var chartDeployment map[string]any
	for _, doc := range docs {
		if doc["kind"] == "Deployment" {
			chartDeployment = doc
		}
	}
	if chartDeployment == nil {
		t.Fatal("chart Deployment missing")
	}
	chartDeployment["metadata"].(map[string]any)["namespace"] = "signature-demo"
	run("signed-chart-deployment", "allowed", chartDeployment, create...)
	run("unsigned-pod", "signature-denied", pod("unsigned-pod", "signature-demo", inputs.UnsignedImage), create...)
	sidecar := pod("unsigned-sidecar", "signature-demo", inputs.SignedImage)
	sidecar["spec"].(map[string]any)["containers"] = []any{container("service", inputs.SignedImage), container("sidecar", inputs.UnsignedImage)}
	run("unsigned-sidecar", "signature-denied", sidecar, create...)
	init := pod("unsigned-init", "signature-demo", inputs.SignedImage)
	init["spec"].(map[string]any)["initContainers"] = []any{container("init", inputs.UnsignedImage)}
	run("unsigned-init", "signature-denied", init, create...)
	chartDeployment["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"] = inputs.UnsignedImage
	run("unsigned-chart-deployment", "signature-denied", chartDeployment, create...)
	run("unmatched-repository", "no-policy-denied", pod("unmatched", "signature-demo", inputs.Controller.Image), create...)
	for _, ephemeral := range []struct{ name, image, expected string }{{"signed-ephemeral", inputs.SignedImage, "allowed"}, {"unsigned-ephemeral", inputs.UnsignedImage, "signature-denied"}} {
		var object map[string]any
		if err := json.Unmarshal(must(nil, "-n", "signature-demo", "get", "pod", "admitted-base", "-o", "json"), &object); err != nil {
			t.Fatal(err)
		}
		debug := container("debug", ephemeral.image)
		delete(debug, "resources")
		object["spec"].(map[string]any)["ephemeralContainers"] = []any{debug}
		path := "/api/v1/namespaces/signature-demo/pods/admitted-base/ephemeralcontainers?dryRun=All"
		run(ephemeral.name, ephemeral.expected, object, "replace", "--raw", path, "-f", "-")
	}
	policyRaw, err := os.ReadFile("../integration/admission/release-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	applyTrust := func(issuer, subject string) {
		var p map[string]any
		if err := json.Unmarshal(policyRaw, &p); err != nil {
			t.Fatal(err)
		}
		identity := p["spec"].(map[string]any)["authorities"].([]any)[0].(map[string]any)["keyless"].(map[string]any)["identities"].([]any)[0].(map[string]any)
		identity["issuer"], identity["subject"] = issuer, subject
		must(request(p), "apply", "-f", "-")
	}
	applyTrust(inputs.Issuer, strings.Replace(inputs.Subject, "release.yml", "unexpected.yml", 1))
	run("wrong-workflow", "identity-denied", pod("wrong-workflow", "signature-demo", inputs.SignedImage), create...)
	applyTrust("https://invalid.invalid", inputs.Subject)
	run("wrong-issuer", "identity-denied", pod("wrong-issuer", "signature-demo", inputs.SignedImage), create...)
	applyTrust(inputs.Issuer, inputs.Subject)
	run("trust-restored", "allowed", pod("trust-restored", "signature-demo", inputs.SignedImage), create...)
	run("outside-enrolled-namespace", "allowed", pod("outside", "signature-outside", inputs.UnsignedImage), create...)
	// Keep the real image-signature policy active while independently exercising
	// attestation trust and both required predicates. No fixture policy is installed
	// by the reusable installer.
	attestationRaw, err := os.ReadFile("../integration/admission/attestations-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	applyAttestations := func(change func(map[string]any)) {
		var p map[string]any
		if err := json.Unmarshal(attestationRaw, &p); err != nil {
			t.Fatal(err)
		}
		authority := p["spec"].(map[string]any)["authorities"].([]any)[0].(map[string]any)
		if change != nil {
			change(authority)
		}
		must(request(p), "apply", "-f", "-")
	}
	for _, tc := range []struct{ name, issuer, subject string }{
		{"attestation-wrong-workflow", inputs.Issuer, strings.Replace(inputs.Subject, "release.yml", "unexpected.yml", 1)},
		{"attestation-wrong-issuer", "https://invalid.invalid", inputs.Subject},
	} {
		applyAttestations(func(a map[string]any) {
			a["keyless"] = map[string]any{"identities": []any{map[string]string{"issuer": tc.issuer, "subject": tc.subject}}}
		})
		run(tc.name, "identity-denied", pod(tc.name, "signature-demo", inputs.SignedImage), create...)
	}
	applyAttestations(nil)
	run("attestation-trust-restored", "allowed", pod("attestation-trust-restored", "signature-demo", inputs.SignedImage), create...)
	var fixtures struct {
		Image, PublicKey string
		Fixtures         map[string]struct{ Source string }
	}
	fixtureRaw, err := os.ReadFile(os.Getenv("TEST_ADMISSION_FIXTURES"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixtureRaw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if fixtures.Image != inputs.SignedImage || !strings.Contains(fixtures.PublicKey, "BEGIN PUBLIC KEY") || len(fixtures.Fixtures) != 9 {
		t.Fatal("invalid disposable fixture inventory")
	}
	useFixture := func(name string) {
		source := fixtures.Fixtures[name].Source
		if !strings.HasPrefix(source, "attestation-registry.test:5000/fixtures/") {
			t.Fatal("fixture source must be the disposable TLS registry")
		}
		applyAttestations(func(a map[string]any) {
			delete(a, "keyless")
			delete(a, "ctlog")
			a["key"] = map[string]string{"data": fixtures.PublicKey}
			a["source"] = []any{map[string]string{"oci": source}}
		})
	}
	for _, name := range []string{"complete", "missing-sbom", "missing-evidence", "invalid-sbom", "evidence-image-mismatch", "evidence-revision-mismatch", "untrusted-sbom", "tampered-evidence", "wrong-subject-evidence"} {
		useFixture(name)
		expected := "attestation-denied"
		if name == "complete" {
			expected = "allowed"
		}
		run("attestation-"+name, expected, pod("attestation-"+name, "signature-demo", inputs.SignedImage), create...)
	}
	useFixture("complete")
	run("fixture-requirements-restored", "allowed", pod("fixture-requirements-restored", "signature-demo", inputs.SignedImage), create...)
	applyAttestations(nil)
	run("release-requirements-restored", "allowed", pod("release-requirements-restored", "signature-demo", inputs.SignedImage), create...)
	runningVerifiers := func() []string {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", "exec", name+"-control-plane", "crictl", "ps", "-o", "json").Output()
		if err != nil {
			t.Fatalf("cannot inspect verifier runtime: %v", err)
		}
		var runtime struct {
			Containers []struct {
				ID     string
				Labels map[string]string
			}
		}
		if err := json.Unmarshal(out, &runtime); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, container := range runtime.Containers {
			if container.Labels["io.kubernetes.pod.namespace"] == "image-policy-system" {
				ids = append(ids, container.ID)
			}
		}
		return ids
	}
	if len(runningVerifiers()) == 0 {
		t.Fatal("runtime positive control did not find any verifier container")
	}
	// Stop the verifier, including its existing connections. Endpoint removal alone
	// does not interrupt an already-established API-server HTTP connection.
	must(nil, "-n", "image-policy-system", "scale", "deployment/policy-controller-webhook", "--replicas=0")
	t.Cleanup(func() {
		_, _ = command(nil, "-n", "image-policy-system", "scale", "deployment/policy-controller-webhook", "--replicas=1")
	})
	// Forced deletion is confined to this disposable cluster and test namespace.
	must(nil, "-n", "image-policy-system", "delete", "pods", "-l", "app.kubernetes.io/instance=policy-controller", "--grace-period=0", "--force", "--wait=true")
	deadline := time.Now().Add(30 * time.Second)
	for {
		var slices struct {
			Items []struct {
				Endpoints []struct{ Conditions struct{ Ready *bool } }
			}
		}
		if err := json.Unmarshal(must(nil, "-n", "image-policy-system", "get", "endpointslices", "-l", "kubernetes.io/service-name=webhook", "-o", "json"), &slices); err != nil {
			t.Fatal(err)
		}
		// The controller has a long drain period. Terminate only its test
		// runtime task so no existing admission connection can survive.
		for _, id := range runningVerifiers() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			out, err := exec.CommandContext(ctx, "docker", "exec", name+"-control-plane", "ctr", "--namespace=k8s.io", "tasks", "kill", "--signal", "SIGKILL", id).CombinedOutput()
			cancel()
			if err != nil && len(runningVerifiers()) != 0 {
				t.Fatalf("cannot stop verifier test task: %v %s", err, out)
			}
		}
		ready := 0
		for _, s := range slices.Items {
			for _, e := range s.Endpoints {
				if e.Conditions.Ready != nil && *e.Conditions.Ready {
					ready++
				}
			}
		}
		if ready == 0 && len(runningVerifiers()) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("verifier endpoints/process did not stop")
		}
		time.Sleep(200 * time.Millisecond)
	}
	run("verifier-unavailable-fail-closed", "unavailable", pod("verifier-unavailable", "signature-demo", inputs.SignedImage), create...)
	run("outside-scope-during-outage", "allowed", pod("outside-outage", "signature-outside", inputs.UnsignedImage), create...)
	must(nil, "-n", "image-policy-system", "scale", "deployment/policy-controller-webhook", "--replicas=1")
	deadline = time.Now().Add(120 * time.Second)
	for {
		var restored struct {
			Status struct{ AvailableReplicas int }
		}
		if err := json.Unmarshal(must(nil, "-n", "image-policy-system", "get", "deployment", "policy-controller-webhook", "-o", "json"), &restored); err != nil {
			t.Fatal(err)
		}
		if restored.Status.AvailableReplicas == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("verifier did not recover")
		}
		time.Sleep(time.Second)
	}
	run("verifier-restored", "allowed", pod("verifier-restored", "signature-demo", inputs.SignedImage), create...)
	evidence.Outcome = "passed"
}

func classifyAdmission(exit int, out string) string {
	if exit == 0 {
		var object struct{ Kind string }
		if json.Unmarshal([]byte(out), &object) == nil && (object.Kind == "Pod" || object.Kind == "Deployment") {
			return "allowed"
		}
		return "other"
	}
	text := strings.ToLower(out)
	if strings.Contains(text, "failed calling webhook") && strings.Contains(text, "policy.sigstore.dev") && (strings.Contains(text, "no endpoints available") || strings.Contains(text, "connection refused") || strings.Contains(text, "context deadline exceeded") || strings.Contains(text, "i/o timeout")) {
		return "unavailable"
	}
	for _, failure := range []string{"i/o timeout", "context deadline exceeded", "too many requests", "connection reset", "tls handshake", "unexpected eof"} {
		if strings.Contains(text, failure) {
			return "other"
		}
	}
	if !strings.Contains(text, "admission webhook") || !strings.Contains(text, "policy.sigstore.dev") || !strings.Contains(text, "denied the request") {
		return "other"
	}
	if strings.Contains(text, "none of the expected identities matched") {
		return "identity-denied"
	}
	if strings.Contains(text, "no matching policies") {
		return "no-policy-denied"
	}
	if strings.Contains(text, "no signatures found") || strings.Contains(text, "no matching signatures") {
		return "signature-denied"
	}
	if strings.Contains(text, "failed policy: release-attestations") && (strings.Contains(text, "no matching attestations") ||
		(strings.Contains(text, "failed evaluating cue policy for release-") && strings.Contains(text, "failed to evaluate the policy with error:"))) {
		return "attestation-denied"
	}
	return "other"
}
