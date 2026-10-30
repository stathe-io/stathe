package scan

import (
	"strings"
	"testing"
)

// A mounted runtime socket is control of the node. A read-only /usr is not.
// Reporting both at high, on their own lines, hands the reader the ranking job
// stathe is supposed to have done.
func TestHostPathsAreRanked(t *testing.T) {
	tests := []struct {
		path     string
		wantRisk Risk
		wantSaid string
	}{
		{"/var/run/docker.sock", High, "control of the node"},
		{"/run/containerd/containerd.sock", High, "control of the node"},
		{"/run/k3s/containerd/containerd.sock", High, "control of the node"},
		{"/var/lib/rancher/rke2/agent/containerd", High, "control of the node"},
		{"/var/lib/kubelet/pki", High, "control of the node"},
		{"/etc/kubernetes/admin.conf", High, "control of the node"},
		{"/", High, "entire node filesystem"},
		{"/etc/systemd/system", High, "what the node runs"},
		{"/root/.ssh", High, "what the node runs or who may log into it"},
		{"/proc", Medium, "processes, devices or logs"},
		{"/var/log/pods", Medium, "processes, devices or logs"},
		{"/usr/share/ca-certificates", Medium, "mounts the node filesystem at /usr/share/ca-certificates"},
		{"/opt/vendor/data", Medium, "mounts the node filesystem at /opt/vendor/data"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			f, ok := hostPathFinding("shop/deployment/app", []string{tt.path})
			if !ok {
				t.Fatalf("expected a finding for %s", tt.path)
			}
			if f.Risk != tt.wantRisk {
				t.Errorf("expected %q for %s, got %q (%s)", tt.wantRisk, tt.path, f.Risk, f.Detail)
			}
			if !strings.Contains(f.Detail, tt.wantSaid) {
				t.Errorf("expected the detail for %s to say %q, got %q", tt.path, tt.wantSaid, f.Detail)
			}
		})
	}
}

// A workload with three host mounts has one thing wrong with it, not three.
func TestHostPathsCollapseToOneFindingWordedAroundTheWorst(t *testing.T) {
	f, ok := hostPathFinding("falco/daemonset/falco", []string{
		"/var/log",
		"/run/containerd/containerd.sock",
		"/proc",
	})
	if !ok {
		t.Fatal("expected a finding")
	}

	if f.Risk != High {
		t.Errorf("the risk has to follow the worst path, got %q", f.Risk)
	}
	if !strings.Contains(f.Detail, "control of the node") {
		t.Errorf("the finding has to be worded around the runtime socket, got %q", f.Detail)
	}
	for _, other := range []string{"/var/log", "/proc"} {
		if !strings.Contains(f.Detail, other) {
			t.Errorf("the other mounts still have to be listed; %s is missing from %q", other, f.Detail)
		}
	}
	if f.Cause != "/run/containerd/containerd.sock" {
		t.Errorf("the worst path is what workloads sharing a chart have in common, got %q", f.Cause)
	}
}

func TestNoHostPathsIsNoFinding(t *testing.T) {
	if _, ok := hostPathFinding("shop/deployment/app", nil); ok {
		t.Error("expected no finding when nothing is mounted from the node")
	}
}

// Jobs, CronJobs and bare pods were invisible until now: a CI build pod is
// often the most privileged workload on a cluster and belongs to no Deployment.
func TestJobsCronJobsAndBarePodsAreAssessed(t *testing.T) {
	privileged := map[string]interface{}{
		"name":            "build",
		"image":           "builder@sha256:abc",
		"securityContext": map[string]interface{}{"privileged": true},
	}

	job := Resource{
		Kind:     "Job",
		Metadata: Metadata{Name: "nightly", Namespace: "ci"},
		Spec: map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{"containers": []interface{}{privileged}},
			},
		},
	}

	cron := Resource{
		Kind:     "CronJob",
		Metadata: Metadata{Name: "rotate", Namespace: "ci"},
		Spec: map[string]interface{}{
			"jobTemplate": map[string]interface{}{
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{"containers": []interface{}{privileged}},
					},
				},
			},
		},
	}

	bare := Resource{
		Kind:     "Pod",
		Metadata: Metadata{Name: "runner-xyz", Namespace: "ci"},
		Spec:     map[string]interface{}{"containers": []interface{}{privileged}},
	}

	for _, r := range []Resource{job, cron, bare} {
		t.Run(r.Kind, func(t *testing.T) {
			if len(r.Containers()) != 1 {
				t.Fatalf("the pod template of a %s is not being read", r.Kind)
			}
			got := CheckPrivileged([]Resource{r})
			if len(got) == 0 {
				t.Fatalf("a privileged %s has to be reported", r.Kind)
			}
		})
	}
}

// A pod a controller created is that controller's pod template with a
// generated name. Reporting both is one finding twice, and the copy with the
// random suffix is the one that is gone by the time anybody reads the report.
func TestPodsOwnedByAControllerAreNotAssessedTwice(t *testing.T) {
	owned := Resource{
		Kind: "Pod",
		Metadata: Metadata{
			Name:            "web-7d9f8b6c4-xk2mq",
			Namespace:       "shop",
			OwnerReferences: []OwnerReference{{Kind: "ReplicaSet", Name: "web-7d9f8b6c4"}},
		},
		Spec: map[string]interface{}{"containers": []interface{}{
			map[string]interface{}{"name": "web", "image": "nginx:latest"},
		}},
	}
	bare := Resource{
		Kind:     "Pod",
		Metadata: Metadata{Name: "debug", Namespace: "shop"},
		Spec: map[string]interface{}{"containers": []interface{}{
			map[string]interface{}{"name": "debug", "image": "nginx:latest"},
		}},
	}

	inv := &Inventory{}
	inv.Add(owned)
	inv.Add(bare)

	if len(inv.Resources) != 1 || inv.Resources[0].Metadata.Name != "debug" {
		t.Fatalf("expected only the bare pod to be assessed, got %d: %+v", len(inv.Resources), inv.Resources)
	}

	// Not an exclusion either: it is the same object as its controller, not
	// something held out of scope, so it does not belong under NOT ASSESSED.
	for _, s := range inv.Skipped() {
		if strings.Contains(s.What, "shop") {
			t.Errorf("a controller's own pod is not a scope exclusion, got %q", s.What)
		}
	}
}
