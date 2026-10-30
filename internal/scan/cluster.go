package scan

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

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

	// optional marks a type the assessment works without. Preflight reports it
	// as unavailable rather than as a no-go: refusing to start because a
	// nice-to-have is missing would be its own kind of dishonesty about what
	// stathe needs.
	optional bool
}{
	{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, "Deployment", true, false},
	{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, "StatefulSet", true, false},
	{schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, "DaemonSet", true, false},
	{schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, "Job", true, false},
	{schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}, "CronJob", true, false},

	// Bare pods only: Add drops the ones a listed controller created. A CI
	// system that starts a build pod per job is often running the most
	// privileged workload on the cluster, and until now stathe could not see it
	// at all -- which means a clean result for a team namespace could have been
	// the blind spot rather than the truth.
	{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}, "Pod", true, false},
	{schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}, "ConfigMap", true, false},
	{schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}, "NetworkPolicy", true, false},
	{schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}, "ClusterRoleBinding", false, false},

	// Read to notice a control that may already handle SC-07, never to suppress
	// it: see ImagePolicyNotes. A cluster without this API is not an error --
	// LoadCluster notes the missing type and carries on.
	{schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: "v1", Resource: "validatingadmissionpolicies"}, "ValidatingAdmissionPolicy", false, true},
}

// defaultPlatformNamespaces are the namespaces every Kubernetes cluster has
// for its own components. They belong to the distribution rather than to the
// team being assessed, and reporting on them buries the findings the team can
// actually act on.
//
// This list is deliberately short, and that is a limitation rather than a
// design: a real cluster also runs a GitOps controller, a policy engine and a
// runtime-security agent, all in namespaces stathe cannot guess. Those get
// reported as team findings unless the person running the assessment says
// otherwise, which is what --platform-namespaces is for.
//
// Skipping is counted, never silent: see Inventory.Skipped. A filter the reader
// cannot see is indistinguishable from a cluster that has nothing wrong with it.
var defaultPlatformNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
	"local-path-storage",
}

var skipNamespaces = namespaceSet(defaultPlatformNamespaces)

// declaredPlatformNamespaces are the ones named on the command line, kept apart
// from the defaults because they apply in one more place: a directory of
// manifests is otherwise assessed exactly as given, but somebody who says a
// namespace is the platform's means it whether stathe is reading a cluster or
// files.
var declaredPlatformNamespaces = map[string]bool{}

// AddPlatformNamespaces adds namespaces to the set treated as the platform's
// own, and returns the whole set sorted.
//
// The returned list goes into the document: which namespaces an assessment
// considered out of scope is part of what it did, and two assessments are only
// comparable if that answer is recorded rather than remembered.
func AddPlatformNamespaces(extra ...string) []string {
	for _, ns := range extra {
		if ns = strings.TrimSpace(ns); ns != "" {
			skipNamespaces[ns] = true
			declaredPlatformNamespaces[ns] = true
		}
	}
	return PlatformNamespaces()
}

// PlatformNamespaces lists the namespaces currently treated as the platform's.
func PlatformNamespaces() []string {
	out := make([]string, 0, len(skipNamespaces))
	for ns := range skipNamespaces {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// IsDefaultPlatformNamespace reports whether a namespace is skipped because
// every cluster has it, rather than because somebody said so on the command
// line. The reason given for an exclusion has to be the real one.
func IsDefaultPlatformNamespace(ns string) bool {
	for _, d := range defaultPlatformNamespaces {
		if d == ns {
			return true
		}
	}
	return false
}

func namespaceSet(list []string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, ns := range list {
		out[ns] = true
	}
	return out
}

// LoadCluster reads configuration from a live cluster. It only ever lists and
// gets; nothing here writes. Pass an empty context name to use the current one
// from the kubeconfig.
//
// The returned Inventory carries both what will be assessed and what was
// skipped, because the caller has to be able to print the second half.
func LoadCluster(ctxName string) (*Inventory, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	if ctxName != "" {
		overrides.CurrentContext = ctxName
	}

	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, KubeconfigError(err)
	}

	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %w", err)
	}

	ctx := context.Background()

	// The resolved context and API server, not the string that was typed. An
	// assessment of the wrong cluster is the one mistake here that cannot be
	// corrected afterwards, and "the current context" on screen is no help to
	// anyone trying to spot it.
	inv := &Inventory{Context: ctxName, Server: cfg.Host}
	if inv.Context == "" {
		if raw, rerr := cc.RawConfig(); rerr == nil {
			inv.Context = raw.CurrentContext
		}
	}

	// The same three lines preflight prints, from the same source, so a reader
	// comparing yesterday's go/no-go with today's run is comparing like with
	// like. A version stathe could not read is left blank rather than guessed.
	inv.Version, _ = serverVersion(cfg)

	for _, w := range wanted {
		list, err := client.Resource(w.gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			// A missing resource type is not fatal: not every cluster has every
			// API, and a partial assessment that says so beats none at all.
			//
			// This goes to stderr and into the document's exclusions, not to
			// stdout: with --json, stdout is the document, and a note printed
			// into it would break every pipeline that parses the output.
			fmt.Fprintf(os.Stderr, "  note: could not read %s (%v)\n", w.gvr.Resource, err)

			reason := fmt.Sprintf("could not be read: %v", err)
			if w.optional {
				reason = fmt.Sprintf("not read, and not needed for the checks: %v", err)
			}
			inv.unread = append(inv.unread, Suppressed{
				What:   "every " + w.gvr.Resource,
				Reason: reason,
			})
			continue
		}

		for _, item := range list.Items {
			// Add applies the namespace filter and counts what it drops; the
			// filter lives there so nothing can be left out uncounted.
			inv.Add(fromUnstructured(item.Object, w.kind, item.GetName(), item.GetNamespace()))
		}
	}

	if len(inv.Resources) == 0 {
		return nil, fmt.Errorf("no resources read; check that the context is right and that you have read access")
	}

	inv.Notes = ImagePolicyNotes(inv.Resources)
	return inv, nil
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

	// Owner references decide whether a pod is its own workload or a copy of a
	// controller's template; see Resource.OwnedByAController.
	if meta, ok := obj["metadata"].(map[string]interface{}); ok {
		if owners, ok := meta["ownerReferences"].([]interface{}); ok {
			for _, o := range owners {
				m, ok := o.(map[string]interface{})
				if !ok {
					continue
				}
				ownerKind, _ := m["kind"].(string)
				ownerName, _ := m["name"].(string)
				r.Metadata.OwnerReferences = append(r.Metadata.OwnerReferences,
					OwnerReference{Kind: ownerKind, Name: ownerName})
			}
		}
	}

	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		r.Spec = spec
	}

	if data, ok := obj["data"].(map[string]interface{}); ok {
		r.Data = map[string]string{}
		for k, v := range data {
			// Only the key is needed to spot a credential. The value is
			// deliberately not copied: the API returns it in the list response
			// (there is no keys-only call), but it is dropped here and never
			// stored, logged or reported. Keep the README wording in step.
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
