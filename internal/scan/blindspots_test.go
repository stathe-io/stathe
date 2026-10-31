package scan

import (
	"strings"
	"testing"
)

// The demo cluster's postgres sets POSTGRES_PASSWORD as a literal in the pod
// spec, and SC-04 did not see it because it only read ConfigMap keys. A
// password in an env value is as readable as one in a ConfigMap -- to anyone
// who can read the Deployment, and to everyone with the repository -- so it is
// the same finding.
func TestCredentialInAnEnvValueIsReported(t *testing.T) {
	d := deployment("postgres", "orders", map[string]interface{}{
		"name":  "postgres",
		"image": "postgres:13-alpine",
		"env": []interface{}{
			map[string]interface{}{"name": "POSTGRES_USER", "value": "northwind"},
			map[string]interface{}{"name": "POSTGRES_PASSWORD", "value": "hunter2-demo-only"},
		},
	})

	got := CheckPlainCredentials([]Resource{d})
	if len(got) != 1 {
		t.Fatalf("expected one SC-04 finding for the env password, got %d: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Detail, "POSTGRES_PASSWORD") || !strings.Contains(got[0].Detail, `"postgres"`) {
		t.Errorf("the detail has to name the container and the variable, got %q", got[0].Detail)
	}
	if strings.Contains(got[0].Detail, "hunter2") {
		t.Errorf("the value must never be reported, got %q", got[0].Detail)
	}
}

// A variable that takes its value from a Secret is the fix, not the problem,
// and a name that only resembles a credential is not one.
func TestEnvFromASecretIsNotReported(t *testing.T) {
	d := deployment("api", "shop", map[string]interface{}{
		"name": "api",
		"env": []interface{}{
			map[string]interface{}{"name": "DB_PASSWORD", "valueFrom": map[string]interface{}{
				"secretKeyRef": map[string]interface{}{"name": "db", "key": "password"},
			}},
			map[string]interface{}{"name": "PASSWORD_MIN_LENGTH", "value": "12"},
		},
	})
	if got := CheckPlainCredentials([]Resource{d}); len(got) != 0 {
		t.Errorf("expected nothing, got %+v", got)
	}
}

// CNI and storage agents commonly do their privileged work in an init
// container. Reading only containers made that invisible.
func TestPrivilegedInitContainerIsReported(t *testing.T) {
	d := deployment("agent", "storage", map[string]interface{}{
		"name":            "agent",
		"image":           "agent@sha256:abc",
		"securityContext": map[string]interface{}{"runAsNonRoot": true},
		"resources":       map[string]interface{}{"limits": map[string]interface{}{"memory": "64Mi"}},
	})
	spec := d.PodSpec()
	spec["initContainers"] = []interface{}{
		map[string]interface{}{
			"name":            "setup",
			"image":           "busybox:latest",
			"securityContext": map[string]interface{}{"privileged": true},
		},
	}

	priv := CheckPrivileged([]Resource{d})
	if len(priv) != 1 || !strings.Contains(priv[0].Detail, `init container "setup"`) {
		t.Errorf("expected the privileged init container to be named, got %+v", priv)
	}

	tags := CheckMutableTags([]Resource{d})
	if len(tags) != 1 || !strings.Contains(tags[0].Detail, "busybox:latest") {
		t.Errorf("expected the init container's floating tag, got %+v", tags)
	}
}

// The dynamic client decodes JSON numbers as int64, YAML decodes them as int.
// The root check asserted int, so on a live cluster it never fired.
func TestRootFromALiveClusterIsReported(t *testing.T) {
	r := fromUnstructured(map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":            "app",
							"securityContext": map[string]interface{}{"runAsUser": int64(0)},
						},
					},
				},
			},
		},
	}, "Deployment", "app", "shop")

	got := CheckPrivileged([]Resource{r})
	if !anyDetailContains(got, "runs as root") {
		t.Errorf("runAsUser 0 read from the cluster has to be reported, got %+v", got)
	}
}
