//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		t.Fatalf("docker %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestHardenedContainer(t *testing.T) {
	image := os.Getenv("TEST_IMAGE")
	if image == "" {
		t.Fatal("TEST_IMAGE is required; this test never silently skips")
	}
	id := docker(t, "run", "--detach", "--platform=linux/amd64", "--label=hsc.test=true", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=32", "--memory=64m", "--cpus=0.5", "--publish=127.0.0.1::8080", image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", id).Run() })
	var state []struct {
		Config     struct{ User string }
		HostConfig struct {
			ReadonlyRootfs       bool
			CapDrop, SecurityOpt []string
		}
	}
	if err := json.Unmarshal([]byte(docker(t, "inspect", id)), &state); err != nil {
		t.Fatal(err)
	}
	if len(state) != 1 || state[0].Config.User != "65532:65532" || !state[0].HostConfig.ReadonlyRootfs || len(state[0].HostConfig.CapDrop) != 1 || strings.ToUpper(state[0].HostConfig.CapDrop[0]) != "ALL" || !strings.Contains(strings.Join(state[0].HostConfig.SecurityOpt, ","), "no-new-privileges") {
		t.Fatalf("unexpected runtime configuration: %+v", state)
	}
	port := docker(t, "port", id, "8080/tcp")
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for {
		r, err := client.Get("http://" + port + "/healthz")
		if err == nil {
			_ = r.Body.Close()
			if r.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("service did not become healthy: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	out, err := exec.Command("docker", "exec", id, "/service", "--check-runtime").CombinedOutput()
	if err != nil {
		t.Fatalf("runtime diagnostic: %v %s", err, out)
	}
	t.Log(string(out))
}

func TestRuntimeDiagnosticRejectsUnsafeSettings(t *testing.T) {
	image := os.Getenv("TEST_IMAGE")
	if image == "" {
		t.Fatal("TEST_IMAGE is required")
	}
	for _, tc := range []struct {
		name, want string
		flags      []string
	}{
		{"writable-root", "expected read-only rootfs", []string{"--cap-drop=ALL", "--security-opt=no-new-privileges"}},
		{"root-user", "unexpected uid/gid", []string{"--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=0:0"}},
		{"missing-no-new-privileges", "unsafe process status", []string{"--read-only", "--cap-drop=ALL"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"run", "--rm", "--platform=linux/amd64", "--network=none"}, tc.flags...)
			args = append(args, image, "--check-runtime")
			out, err := exec.Command("docker", args...).CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("expected %s denial: %v %s", tc.name, err, out)
			}
		})
	}
}

func TestNoShell(t *testing.T) {
	image := os.Getenv("TEST_IMAGE")
	if image == "" {
		t.Fatal("TEST_IMAGE is required")
	}
	out, err := exec.Command("docker", "run", "--rm", "--network=none", "--entrypoint=/bin/sh", image, "-c", "true").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "/bin/sh") {
		t.Fatalf("expected missing shell, err=%v out=%s", err, out)
	}
	fmt.Println("scratch image rejects /bin/sh")
}
