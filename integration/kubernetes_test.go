//go:build kubernetes

package integration

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestKubernetesDeployment(t *testing.T) {
	config := os.Getenv("TEST_KUBECONFIG")
	if config == "" {
		t.Fatal("TEST_KUBECONFIG is required; never uses the default context")
	}
	kubectl := func(args ...string) *exec.Cmd {
		return exec.Command("kubectl", append([]string{"--kubeconfig", config, "--namespace=supply-demo"}, args...)...)
	}
	t.Run("kernel-runtime-controls", func(t *testing.T) {
		out, err := kubectl("exec", "deployment/demo", "--", "/service", "--check-runtime").CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		t.Log(string(out))
	})
	t.Run("http-through-service", func(t *testing.T) {
		cmd := kubectl("port-forward", "service/demo", ":8080", "--address=127.0.0.1")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		ports := make(chan string, 1)
		go func() {
			s := bufio.NewScanner(stdout)
			for s.Scan() {
				line := s.Text()
				if strings.HasPrefix(line, "Forwarding from 127.0.0.1:") {
					ports <- strings.Fields(line)[2]
					return
				}
			}
		}()
		var address string
		select {
		case address = <-ports:
		case <-time.After(15 * time.Second):
			t.Fatal("port-forward timeout")
		}
		client := &http.Client{Timeout: 3 * time.Second}
		for _, endpoint := range []string{"healthz", "readyz", "version"} {
			r, err := client.Get("http://" + address + "/" + endpoint)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			if r.StatusCode != 200 {
				t.Fatalf("%s status %d", endpoint, r.StatusCode)
			}
			t.Logf("/%s: %s", endpoint, strings.TrimSpace(string(body)))
		}
	})
	t.Run("restricted-admission-rejects-privilege", func(t *testing.T) {
		cmd := kubectl("create", "--dry-run=server", "-f", "-")
		cmd.Stdin = strings.NewReader(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"intentionally-unsafe"},"spec":{"containers":[{"name":"bad","image":"invalid.invalid/never-pulled:fixture","securityContext":{"privileged":true}}]}}`)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "violates PodSecurity") {
			t.Fatalf("expected admission denial: %v %s", err, out)
		}
		fmt.Println("PASS restricted admission rejects privileged pod")
	})
}
