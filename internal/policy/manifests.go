package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type Object = map[string]any

func object(v any) Object { m, _ := v.(map[string]any); return m }
func path(m Object, keys ...string) any {
	var v any = m
	for _, key := range keys {
		v = object(v)[key]
	}
	return v
}
func list(v any) []any  { a, _ := v.([]any); return a }
func text(v any) string { s, _ := v.(string); return s }
func equal(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

var digestImage = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]*@sha256:[a-f0-9]{64}$`)

// DecodeManifests accepts JSON documents separated by YAML document markers.
// The chart emits JSON, a YAML subset; arbitrary YAML is deliberately unsupported.
func DecodeManifests(raw []byte) ([]Object, error) {
	var cleaned []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			cleaned = append(cleaned, line)
		}
	}
	var docs []Object
	for _, part := range strings.Split("\n"+strings.Join(cleaned, "\n"), "\n---\n") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		var doc Object
		if err := json.Unmarshal([]byte(part), &doc); err != nil {
			return nil, fmt.Errorf("expected chart JSON documents: %w", err)
		}
		docs = append(docs, doc)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("empty manifest set")
	}
	return docs, nil
}

// Manifests validates this chart's deliberately narrow four-resource contract.
func Manifests(docs []Object) []string {
	var failures []string
	check := func(ok bool, id string) {
		if !ok {
			failures = append(failures, id)
		}
	}
	byKind := map[string]Object{}
	for _, doc := range docs {
		kind := text(doc["kind"])
		_, duplicate := byKind[kind]
		check(!duplicate, "MANIFEST-DUPLICATE")
		check(kind == "Deployment" || kind == "Service" || kind == "ServiceAccount" || kind == "NetworkPolicy", "MANIFEST-KIND")
		byKind[kind] = doc
	}
	check(len(docs) == 4, "MANIFEST-SET")
	for _, kind := range []string{"Deployment", "Service", "ServiceAccount", "NetworkPolicy"} {
		check(byKind[kind] != nil, "MANIFEST-MISSING-"+kind)
	}
	d := byKind["Deployment"]
	spec := object(path(d, "spec", "template", "spec"))
	labels := path(d, "spec", "selector", "matchLabels")
	check(len(object(labels)) > 0 && equal(labels, path(d, "spec", "template", "metadata", "labels")), "K8S-SELECTOR")
	check(spec["automountServiceAccountToken"] == false, "K8S-TOKEN")
	for _, k := range []string{"hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"} {
		check(spec[k] == nil || spec[k] == false, "K8S-HOST-"+k)
	}
	check(len(list(spec["volumes"])) == 0 && len(list(spec["initContainers"])) == 0 && len(list(spec["ephemeralContainers"])) == 0, "K8S-EXTRA-SURFACE")
	psc := object(spec["securityContext"])
	check(psc["runAsNonRoot"] == true && psc["runAsUser"] == float64(65532) && psc["runAsGroup"] == float64(65532), "K8S-USER")
	check(path(psc, "seccompProfile", "type") == "RuntimeDefault", "K8S-SECCOMP")
	containers := list(spec["containers"])
	check(len(containers) == 1, "K8S-CONTAINERS")
	for _, v := range containers {
		c := object(v)
		sc := object(c["securityContext"])
		check(digestImage.MatchString(text(c["image"])), "K8S-IMAGE-DIGEST")
		check(sc["readOnlyRootFilesystem"] == true, "K8S-READONLY")
		check(sc["allowPrivilegeEscalation"] == false && sc["privileged"] == false, "K8S-PRIVILEGE")
		check(equal(path(sc, "capabilities", "drop"), []any{"ALL"}) && len(list(path(sc, "capabilities", "add"))) == 0, "K8S-CAPABILITIES")
		check(sc["runAsUser"] == nil && sc["runAsGroup"] == nil && sc["runAsNonRoot"] == nil && sc["seccompProfile"] == nil, "K8S-IDENTITY-OVERRIDE")
		check(len(list(c["volumeMounts"])) == 0 && len(list(c["env"])) == 0 && len(list(c["envFrom"])) == 0 && c["command"] == nil && c["args"] == nil, "K8S-CONTAINER-SURFACE")
		for _, scope := range []string{"requests", "limits"} {
			for _, resource := range []string{"cpu", "memory"} {
				check(text(path(c, "resources", scope, resource)) != "", "K8S-RESOURCES")
			}
		}
		for _, probe := range []string{"readinessProbe", "livenessProbe"} {
			check(path(c, probe, "httpGet", "port") == float64(8080), "K8S-PROBE")
		}
	}
	sa := byKind["ServiceAccount"]
	check(sa["automountServiceAccountToken"] == false && path(sa, "metadata", "name") == spec["serviceAccountName"] && text(spec["serviceAccountName"]) != "", "K8S-SERVICEACCOUNT")
	svc := byKind["Service"]
	check(path(svc, "spec", "type") == "ClusterIP" && equal(path(svc, "spec", "selector"), labels), "K8S-SERVICE")
	np := byKind["NetworkPolicy"]
	check(equal(path(np, "spec", "podSelector", "matchLabels"), labels), "NET-SELECTOR")
	check(equal(path(np, "spec", "policyTypes"), []any{"Ingress", "Egress"}) && equal(path(np, "spec", "egress"), []any{}), "NET-DENY-EGRESS")
	expected := []any{Object{"from": []any{Object{"podSelector": Object{}}}, "ports": []any{Object{"protocol": "TCP", "port": float64(8080)}}}}
	check(equal(path(np, "spec", "ingress"), expected), "NET-INGRESS")
	return failures
}
