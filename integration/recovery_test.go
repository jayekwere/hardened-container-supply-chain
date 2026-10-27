//go:build admission

package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type recoveryPod struct {
	Metadata struct{ UID, DeletionTimestamp string }
	Spec     struct{ NodeName string }
	Status   struct {
		PodIP      string
		Conditions []struct{ Type, Status string }
	}
}

func readyRecoveryPods(raw []byte) (map[string]recoveryPod, bool) {
	var list struct{ Items []recoveryPod }
	if json.Unmarshal(raw, &list) != nil || len(list.Items) != 2 {
		return nil, false
	}
	nodes, pods := map[string]bool{}, map[string]recoveryPod{}
	for _, p := range list.Items {
		ready := false
		for _, c := range p.Status.Conditions {
			ready = ready || c.Type == "Ready" && c.Status == "True"
		}
		if !ready || p.Metadata.UID == "" || p.Metadata.DeletionTimestamp != "" || p.Status.PodIP == "" || p.Spec.NodeName == "" || nodes[p.Spec.NodeName] {
			return nil, false
		}
		nodes[p.Spec.NodeName] = true
		pods[p.Metadata.UID] = p
	}
	return pods, len(pods) == 2
}

func healthyRecovery(snapshot map[string]json.RawMessage, expectedNodes []string) bool {
	var nodes struct {
		Items []struct {
			Metadata struct{ Name string }
			Status   struct {
				Conditions []struct{ Type, Status string }
			}
		}
	}
	if json.Unmarshal(snapshot["nodes"], &nodes) != nil || len(nodes.Items) != len(expectedNodes) {
		return false
	}
	readyNodes := map[string]bool{}
	for _, n := range nodes.Items {
		for _, c := range n.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				readyNodes[n.Metadata.Name] = true
			}
		}
	}
	for _, node := range expectedNodes {
		if !readyNodes[node] {
			return false
		}
	}
	pods, ok := readyRecoveryPods(snapshot["verifiers"])
	if !ok {
		return false
	}
	dns, ok := readyRecoveryPods(snapshot["dns"])
	if !ok {
		return false
	}
	for _, group := range []map[string]recoveryPod{pods, dns} {
		for _, p := range group {
			if !readyNodes[p.Spec.NodeName] {
				return false
			}
		}
	}
	var slices struct {
		Items []struct {
			Endpoints []struct {
				Addresses  []string
				NodeName   string
				Conditions struct{ Ready, Terminating bool }
				TargetRef  struct{ UID string }
			}
		}
	}
	if json.Unmarshal(snapshot["endpoints"], &slices) != nil {
		return false
	}
	matched := map[string]bool{}
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			p, found := pods[endpoint.TargetRef.UID]
			if !found || !endpoint.Conditions.Ready || endpoint.Conditions.Terminating || endpoint.NodeName != p.Spec.NodeName || len(endpoint.Addresses) != 1 || endpoint.Addresses[0] != p.Status.PodIP {
				return false
			}
			matched[endpoint.TargetRef.UID] = true
		}
	}
	return len(matched) == 2
}

func TestRecoveryReadiness(t *testing.T) {
	base := map[string]string{
		"nodes":     `{"items":[{"metadata":{"name":"a"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"name":"b"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`,
		"verifiers": `{"items":[{"metadata":{"uid":"v1"},"spec":{"nodeName":"a"},"status":{"podIP":"10.0.0.1","conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"uid":"v2"},"spec":{"nodeName":"b"},"status":{"podIP":"10.0.0.2","conditions":[{"type":"Ready","status":"True"}]}}]}`,
		"dns":       `{"items":[{"metadata":{"uid":"d1"},"spec":{"nodeName":"a"},"status":{"podIP":"10.0.1.1","conditions":[{"type":"Ready","status":"True"}]}},{"metadata":{"uid":"d2"},"spec":{"nodeName":"b"},"status":{"podIP":"10.0.1.2","conditions":[{"type":"Ready","status":"True"}]}}]}`,
		"endpoints": `{"items":[{"endpoints":[{"addresses":["10.0.0.1"],"nodeName":"a","conditions":{"ready":true},"targetRef":{"uid":"v1"}},{"addresses":["10.0.0.2"],"nodeName":"b","conditions":{"ready":true},"targetRef":{"uid":"v2"}}]}]}`,
	}
	for i, change := range []struct{ key, from, to string }{
		{},
		{"nodes", `"status":"True"`, `"status":"Unknown"`},
		{"verifiers", `"status":"True"`, `"status":"False"`},
		{"verifiers", `"nodeName":"b"`, `"nodeName":"a"`},
		{"dns", `"nodeName":"b"`, `"nodeName":"a"`},
		{"dns", `"status":"True"`, `"status":"False"`},
		{"endpoints", `"ready":true`, `"ready":false`},
		{"endpoints", `"ready":true`, `"ready":true,"terminating":true`},
		{"endpoints", `"uid":"v2"`, `"uid":"old-pod"`},
		{"endpoints", `"10.0.0.2"`, `"10.0.0.99"`},
		{"endpoints", `"nodeName":"b"`, `"nodeName":"a"`},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			snapshot := map[string]json.RawMessage{}
			for key, raw := range base {
				if key == change.key {
					raw = strings.ReplaceAll(raw, change.from, change.to)
				}
				snapshot[key] = json.RawMessage(raw)
			}
			if healthyRecovery(snapshot, []string{"a", "b"}) != (i == 0) {
				t.Fatal("incomplete recovery accepted or healthy recovery rejected")
			}
		})
	}
}
