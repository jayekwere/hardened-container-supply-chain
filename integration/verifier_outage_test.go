//go:build admission

package integration

import (
	"errors"
	"fmt"
	"testing"
)

// Kubernetes can stop a task between the runtime inventory and SIGKILL. Check
// that specific task again; another live replica does not make its exit fail.
// The caller still waits for every verifier process and ready endpoint to stop.
func stopVerifierTasks(running func() map[string]string, stop func(string, string) error) error {
	for id, node := range running() {
		if err := stop(id, node); err != nil {
			if _, stillRunning := running()[id]; stillRunning {
				return fmt.Errorf("task %s on %s: %w", id, node, err)
			}
		}
	}
	return nil
}

func TestVerifierTaskStop(t *testing.T) {
	for _, tc := range []struct {
		name      string
		before    map[string]string
		after     map[string]string
		stopError bool
		wantError bool
	}{
		{"already-stopped", nil, nil, false, false},
		{"signal-succeeds", map[string]string{"a": "node-a"}, nil, false, false},
		{"task-exits-before-signal", map[string]string{"a": "node-a"}, nil, true, false},
		{"task-exits-other-replica-still-live", map[string]string{"a": "node-a"}, map[string]string{"b": "node-b"}, true, false},
		{"replacement-does-not-prove-outage", map[string]string{"a": "node-a"}, map[string]string{"new-a": "node-a"}, true, false},
		{"signal-fails-target-still-live", map[string]string{"a": "node-a"}, map[string]string{"a": "node-a"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inventoryCalls, stopCalls := 0, 0
			actual := stopVerifierTasks(func() map[string]string {
				inventoryCalls++
				if inventoryCalls == 1 {
					return tc.before
				}
				return tc.after
			}, func(id, node string) error {
				stopCalls++
				if expected, found := tc.before[id]; !found || expected != node {
					t.Fatalf("signal sent outside inspected inventory: %s %s", id, node)
				}
				if tc.stopError {
					return errors.New("task not found or signal failed")
				}
				return nil
			})
			if (actual != nil) != tc.wantError || stopCalls != len(tc.before) {
				t.Fatalf("error=%v, stop calls=%d", actual, stopCalls)
			}
		})
	}
}
