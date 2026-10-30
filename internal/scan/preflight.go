package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Preflight answers one question, the day before an assessment: if we run
// stathe tomorrow morning, will it work?
//
// This exists because the expensive failure is not a missing check. It is
// arriving at a client, sitting down with four of their engineers, and finding
// out that the account they prepared cannot list ClusterRoleBindings. That
// costs a morning of six people. Asking the API server a day earlier costs
// nothing.
//
// It needs exactly the access `stathe check` needs and not a byte more, which
// is also the point: if preflight passes, the RBAC that was approved is right.

// Access is the verdict on one resource type.
type Access struct {
	Resource string
	Group    string
	Allowed  bool
	Reason   string

	// Optional types do not decide the go/no-go. stathe assesses the cluster
	// without them; all that is lost is a note in the output.
	Optional bool
}

// Platform is what the cluster turned out to be running. Every field is best
// effort: a blank one means stathe could not tell, not that it is absent.
type Platform struct {
	Ingress string
	CNI     string
	GitOps  string
}

// PreflightResult is the whole report. OK is the go/no-go.
type PreflightResult struct {
	Context  string
	Server   string
	Version  string
	Access   []Access
	Platform Platform
	OK       bool
}

// Preflight checks reachability, then permission per resource type, then makes
// a best effort at identifying the platform so the baseline can be prepared in
// advance rather than improvised on the day.
func Preflight(ctxName string) (*PreflightResult, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	if ctxName != "" {
		overrides.CurrentContext = ctxName
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("could not load kubeconfig: %w", err)
	}

	res := &PreflightResult{Context: ctxName, Server: cfg.Host}
	if res.Context == "" {
		if raw, err := cc.RawConfig(); err == nil {
			res.Context = raw.CurrentContext
		}
	}

	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %w", err)
	}

	// Reachability first. Everything below is meaningless if this fails, and
	// the error it returns is the one worth showing a client.
	//
	// This reads /version directly rather than through the typed clientset.
	// Pulling in kubernetes.Interface for two calls doubled the image, and the
	// small distroless image is itself an argument we make to clients.
	res.Version, err = serverVersion(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not reach the API server at %s: %w", cfg.Host, err)
	}

	ctx := context.Background()
	res.OK = true

	// SelfSubjectAccessReview asks the API server what this identity may do.
	// It is the honest way to check: it accounts for every Role, binding and
	// webhook in play, rather than reading RBAC objects and guessing.
	reviews := client.Resource(gvrOf("authorization.k8s.io", "v1", "selfsubjectaccessreviews"))

	for _, w := range wanted {
		a := Access{Resource: w.gvr.Resource, Group: w.gvr.Group, Optional: w.optional}

		review := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "authorization.k8s.io/v1",
			"kind":       "SelfSubjectAccessReview",
			"spec": map[string]interface{}{
				"resourceAttributes": map[string]interface{}{
					"group":    w.gvr.Group,
					"version":  w.gvr.Version,
					"resource": w.gvr.Resource,
					"verb":     "list",
				},
			},
		}}

		out, err := reviews.Create(ctx, review, metav1.CreateOptions{})
		if err != nil {
			// Some managed clusters restrict the review API itself. Fall back
			// to trying the list, which answers the same question less politely.
			a.Allowed, a.Reason = tryList(ctx, cfg, w.gvr.Group, w.gvr.Version, w.gvr.Resource)
		} else {
			allowed, _, _ := unstructured.NestedBool(out.Object, "status", "allowed")
			reason, _, _ := unstructured.NestedString(out.Object, "status", "reason")
			a.Allowed = allowed
			a.Reason = reason
			if !a.Allowed && a.Reason == "" {
				a.Reason = "not permitted for this account"
			}
		}

		if !a.Allowed && !a.Optional {
			res.OK = false
		}
		res.Access = append(res.Access, a)
	}

	res.Platform = detectPlatform(ctx, cfg, res.Version)
	return res, nil
}

// serverVersion reads /version, which every API server exposes to any
// authenticated identity.
//
// This goes over a plain HTTP client built from the kubeconfig rather than
// through a typed client. Pulling in the full clientset for this one call and
// the access reviews doubled the image, and the small distroless image is
// itself an argument we make to clients.
func serverVersion(cfg *rest.Config) (string, error) {
	httpClient, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(cfg.Host, "/")+"/version", nil)
	if err != nil {
		return "", err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the API server answered %s", resp.Status)
	}

	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", fmt.Errorf("could not read the version response: %w", err)
	}
	return v.GitVersion, nil
}

// tryList is the fallback when SelfSubjectAccessReview is unavailable. It asks
// for a single item, which is enough to learn whether the verb is permitted
// without pulling the whole collection.
func tryList(ctx context.Context, cfg *rest.Config, group, version, resource string) (bool, string) {
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return false, "could not create client"
	}
	gvr := gvrOf(group, version, resource)
	if _, err := client.Resource(gvr).List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		return false, short(err.Error())
	}
	return true, "confirmed by listing"
}

// detectPlatform identifies the ingress controller, CNI and GitOps tool from
// the workloads that are running. It deliberately uses only the access stathe
// already has, so preflight never asks a client for more than the assessment
// itself will.
func detectPlatform(ctx context.Context, cfg *rest.Config, serverVersion string) Platform {
	var p Platform

	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return p
	}

	names := map[string]bool{}
	for _, resource := range []string{"deployments", "daemonsets", "statefulsets"} {
		list, err := client.Resource(gvrOf("apps", "v1", resource)).
			List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, item := range list.Items {
			names[item.GetName()] = true
		}
	}

	match := func(table [][2]string) string {
		for _, row := range table {
			for name := range names {
				if strings.Contains(name, row[0]) {
					return row[1]
				}
			}
		}
		return ""
	}

	p.Ingress = match([][2]string{
		{"ingress-nginx-controller", "NGINX Ingress"},
		{"nginx-ingress", "NGINX Ingress"},
		{"traefik", "Traefik"},
		{"haproxy-ingress", "HAProxy Ingress"},
		{"istio-ingressgateway", "Istio ingress gateway"},
		{"contour", "Contour"},
	})
	// The distribution-specific names come first: on RKE2 the CNI DaemonSet is
	// rke2-canal, which matched nothing here and came back as "could not
	// tell" -- a blank that reads as "this cluster has no CNI" when it means
	// "stathe did not recognise the name".
	p.CNI = match([][2]string{
		{"rke2-canal", "Canal (Flannel for networking, Calico for policy), the RKE2 default"},
		{"rke2-cilium", "Cilium, via the RKE2 chart"},
		{"rke2-calico-node", "Calico, via the RKE2 chart"},
		{"canal", "Canal (Flannel for networking, Calico for policy)"},
		{"calico-node", "Calico"},
		{"cilium", "Cilium"},
		{"kube-flannel", "Flannel"},
		{"flannel", "Flannel"},
		{"aws-node", "AWS VPC CNI"},
		{"kube-router", "kube-router"},
		{"antrea-agent", "Antrea"},
		{"weave-net", "Weave Net"},
	})
	if p.CNI == "" {
		p.CNI = cniFromDistribution(serverVersion)
	}
	p.GitOps = match([][2]string{
		{"argocd-application-controller", "Argo CD"},
		{"argocd-server", "Argo CD"},
		{"kustomize-controller", "Flux"},
		{"source-controller", "Flux"},
	})

	return p
}

// cniFromDistribution infers the CNI from the server version string, which
// names the distribution on RKE2 and k3s (for example v1.31.4+rke2r1).
//
// This is a guess and is worded as one. It exists because "could not tell"
// reads as "there is no network policy enforcement here", and the difference
// decides which baseline variant gets prepared the night before -- but a guess
// presented as a fact is worse than the blank it replaced.
func cniFromDistribution(serverVersion string) string {
	v := strings.ToLower(serverVersion)
	switch {
	case strings.Contains(v, "rke2"):
		return "probably Canal, the RKE2 default — inferred from the server version, " +
			"not from a DaemonSet stathe recognised. Confirm during the kickoff."
	case strings.Contains(v, "k3s"):
		return "probably Flannel, the k3s default — inferred from the server version, " +
			"not from a DaemonSet stathe recognised. Confirm during the kickoff."
	case strings.Contains(v, "gke"):
		return "probably GKE's own dataplane — inferred from the server version. Confirm during the kickoff."
	case strings.Contains(v, "eks"):
		return "probably the AWS VPC CNI — inferred from the server version. Confirm during the kickoff."
	}
	return ""
}

// short trims an API error to the part a reader needs. The full text carries
// the whole request, which buries the reason.
func short(s string) string {
	if i := strings.Index(s, ":"); i > 0 && i < len(s)-2 {
		s = strings.TrimSpace(s[i+1:])
	}
	if len(s) > 90 {
		s = s[:90] + "..."
	}
	return s
}

// gvrOf is a shorthand, because the three-field literal makes the tables above
// unreadable.
func gvrOf(group, version, resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
}
