package scan

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

// wanted lists the resource types the checks need. Keeping it explicit matters
// for more than performance: this is the list handed to a security officer who
// asks what the tool reads, and every entry is a read of configuration, never
// of application data or secret values.
var wanted = []struct {
	gvr        schema.GroupVersionResource
	kind       string
	namespaced bool
}{
	{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, "Deployment", true},
	{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, "StatefulSet", true},
	{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, "DaemonSet", true},
	{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, "ConfigMap", true},
	{schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}, "NetworkPolicy", true},
	{schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}, "ClusterRoleBinding", false},
}

// skipNamespaces leaves the platform's own components out of the assessment.
// They belong to the distribution rather than to the team being assessed, and
// reporting on them buries the findings the team can actually act on.
var skipNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"local-path-storage": true,
}

// LoadCluster reads configuration from a live cluster. It only ever lists and
// gets; nothing here writes. Pass an empty context name to use the current one
// from the kubeconfig.
func LoadCluster(ctxName string) ([]Resource, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	if ctxName != "" {
		overrides.CurrentContext = ctxName
	}

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("could not load kubeconfig: %w", err)
	}

	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %w", err)
	}

	ctx := context.Background()
	var out []Resource

	for _, w := range wanted {
		list, err := client.Resource(w.gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			// A missing resource type is not fatal: not every cluster has every
			// API, and a partial assessment with a warning beats none at all.
			fmt.Printf("  note: could not read %s (%v)\n", w.gvr.Resource, err)
			continue
		}

		for _, item := range list.Items {
			ns := item.GetNamespace()
			if skipNamespaces[ns] {
				continue
			}
			out = append(out, fromUnstructured(item.Object, w.kind, item.GetName(), ns))
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no resources read; check that the context is right and that you have read access")
	}
	return out, nil
}

// fromUnstructured maps an API object onto the same Resource shape the manifest
// loader produces, so every check works identically against files and clusters.
func fromUnstructured(obj map[string]interface{}, kind, name, ns string) Resource {
	r := Resource{
		Kind:   kind,
		Source: "cluster",
		Metadata: Metadata{
			Name:      name,
			Namespace: ns,
		},
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		r.Spec = spec
	}

	if data, ok := obj["data"].(map[string]interface{}); ok {
		r.Data = map[string]string{}
		for k, v := range data {
			// Only the key is needed to spot a credential. The value is
			// deliberately not copied: the tool never carries secret material
			// around, which keeps it honest when a client asks.
			_ = v
			r.Data[k] = ""
		}
	}

	if ref, ok := obj["roleRef"].(map[string]interface{}); ok {
		r.RoleRef = map[string]string{}
		for k, v := range ref {
			if s, ok := v.(string); ok {
				r.RoleRef[k] = s
			}
		}
	}

	if subjects, ok := obj["subjects"].([]interface{}); ok {
		for _, s := range subjects {
			m, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			subject := map[string]string{}
			for k, v := range m {
				if str, ok := v.(string); ok {
					subject[k] = str
				}
			}
			r.Subjects = append(r.Subjects, subject)
		}
	}

	return r
}
