package policy

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) []Object {
	t.Helper()
	raw, err := os.ReadFile("testdata/pass.json.yaml")
	if err != nil {
		t.Fatal(err)
	}
	docs, err := DecodeManifests(raw)
	if err != nil {
		t.Fatal(err)
	}
	return docs
}
func TestManifestPolicy(t *testing.T) {
	if failures := Manifests(fixture(t)); len(failures) != 0 {
		t.Fatal(failures)
	}
	for _, tc := range []struct {
		name, rule string
		mutate     func([]Object)
	}{
		{"root", "K8S-USER", func(d []Object) {
			object(path(d[0], "spec", "template", "spec", "securityContext"))["runAsUser"] = float64(0)
		}},
		{"writable", "K8S-READONLY", func(d []Object) {
			object(path(d[0], "spec", "template", "spec", "containers").([]any)[0])["securityContext"].(map[string]any)["readOnlyRootFilesystem"] = false
		}},
		{"tag", "K8S-IMAGE-DIGEST", func(d []Object) {
			object(list(path(d[0], "spec", "template", "spec", "containers"))[0])["image"] = "demo:latest"
		}},
		{"privileged", "K8S-PRIVILEGE", func(d []Object) {
			object(path(object(list(path(d[0], "spec", "template", "spec", "containers"))[0]), "securityContext"))["privileged"] = true
		}},
		{"token", "K8S-TOKEN", func(d []Object) {
			object(path(d[0], "spec", "template", "spec"))["automountServiceAccountToken"] = true
		}},
		{"host", "K8S-HOST-hostPID", func(d []Object) { object(path(d[0], "spec", "template", "spec"))["hostPID"] = true }},
		{"init", "K8S-EXTRA-SURFACE", func(d []Object) {
			object(path(d[0], "spec", "template", "spec"))["initContainers"] = []any{Object{"name": "bad"}}
		}},
		{"caps", "K8S-CAPABILITIES", func(d []Object) {
			object(path(object(list(path(d[0], "spec", "template", "spec", "containers"))[0]), "securityContext", "capabilities"))["add"] = []any{"SYS_ADMIN"}
		}},
		{"override", "K8S-IDENTITY-OVERRIDE", func(d []Object) {
			object(path(object(list(path(d[0], "spec", "template", "spec", "containers"))[0]), "securityContext"))["runAsUser"] = float64(0)
		}},
		{"egress", "NET-DENY-EGRESS", func(d []Object) {
			for _, v := range d {
				if v["kind"] == "NetworkPolicy" {
					object(v["spec"])["egress"] = []any{Object{}}
				}
			}
		}},
		{"selector", "NET-SELECTOR", func(d []Object) {
			for _, v := range d {
				if v["kind"] == "NetworkPolicy" {
					object(v["spec"])["podSelector"] = Object{}
				}
			}
		}},
		{"resource-kind", "MANIFEST-KIND", func(d []Object) { d[1]["kind"] = "ClusterRole" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := fixture(t)
			tc.mutate(d)
			if !strings.Contains(strings.Join(Manifests(d), ","), tc.rule) {
				b, _ := json.Marshal(d)
				t.Fatalf("missing %s: %s", tc.rule, b)
			}
		})
	}
	if len(Manifests(fixture(t)[:3])) == 0 {
		t.Fatal("missing resource accepted")
	}
	for _, raw := range []string{"", "kind: Deployment", "null", "{}\n{}"} {
		d, err := DecodeManifests([]byte(raw))
		if err == nil && len(Manifests(d)) == 0 {
			t.Fatalf("accepted %q", raw)
		}
	}
}
