package scan

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Resource is a Kubernetes object, kept as loosely typed maps on purpose. The
// checks only ever read a handful of fields, and the typed client-go structs
// would mean rejecting manifests this tool is specifically meant to inspect:
// the broken ones.
type Resource struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   Metadata               `yaml:"metadata"`
	Spec       map[string]interface{} `yaml:"spec"`
	Data       map[string]string      `yaml:"data"`
	RoleRef    map[string]string      `yaml:"roleRef"`
	Subjects   []map[string]string    `yaml:"subjects"`

	// Rules are a (Cluster)Role's permissions. SC-06 reads them because the
	// name of a role says nothing about what it grants: a ClusterRole with
	// wildcards everywhere is cluster-admin whatever it is called.
	Rules []PolicyRule `yaml:"rules"`

	Source string `yaml:"-"`
}

// PolicyRule is one rule from a (Cluster)Role, with the fields that decide how
// much it grants. NonResourceURLs is deliberately absent: it covers endpoints
// like /healthz, and no combination of them is control of the cluster.
type PolicyRule struct {
	APIGroups []string `yaml:"apiGroups"`
	Resources []string `yaml:"resources"`
	Verbs     []string `yaml:"verbs"`
}

// GrantsEverything reports whether a rule allows every action on every
// resource in every API group.
//
// All three have to be wildcarded on the same rule. "Read everything" plus
// "do anything to Jobs" is two useful-but-bounded rules, and a check that
// ORed the fields together would call that combination cluster-admin -- which
// is the kind of false positive that teaches a reader to skip the check.
func (r PolicyRule) GrantsEverything() bool {
	return hasWildcard(r.APIGroups) && hasWildcard(r.Resources) && hasWildcard(r.Verbs)
}

func hasWildcard(xs []string) bool {
	for _, x := range xs {
		if strings.TrimSpace(x) == "*" {
			return true
		}
	}
	return false
}

type Metadata struct {
	Name      string            `yaml:"name"`
	Namespace string            `yaml:"namespace"`
	Labels    map[string]string `yaml:"labels"`

	// OwnerReferences says what created this object. A Pod created by a
	// Deployment is the Deployment's pod template over again, and reporting
	// both is the same finding twice with two different names on it.
	OwnerReferences []OwnerReference `yaml:"ownerReferences"`
}

// OwnerReference is the part of an owner reference the checks use.
type OwnerReference struct {
	Kind string `yaml:"kind"`
	Name string `yaml:"name"`
}

// Ref names the resource the way a reader would look it up with kubectl.
func (r Resource) Ref() string {
	if r.Metadata.Namespace == "" {
		return fmt.Sprintf("%s/%s", strings.ToLower(r.Kind), r.Metadata.Name)
	}
	return fmt.Sprintf("%s/%s/%s", r.Metadata.Namespace, strings.ToLower(r.Kind), r.Metadata.Name)
}

// templatedKinds carry a pod template under spec.template.
var templatedKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"Job":         true,
}

// controllerKinds are the kinds that own pods, so a pod owned by one of them
// is already covered by assessing the controller. CronJob owns Jobs, which own
// the pods, which is why Job appears in both maps.
var controllerKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
	"Job":         true,
	"ReplicaSet":  true,
	"CronJob":     true,
}

// Containers returns the pod containers for workload kinds, and nil otherwise,
// so callers can range over the result without checking the kind first.
func (r Resource) Containers() []map[string]interface{} {
	podSpec := r.PodSpec()
	if podSpec == nil {
		return nil
	}

	raw, ok := podSpec["containers"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, c := range raw {
		if m, ok := c.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

// PodSpec exposes the pod-level spec for checks that look above the container,
// such as serviceAccountName or volumes.
//
// A CronJob nests one level deeper than everything else
// (spec.jobTemplate.spec.template.spec), which is worth handling rather than
// skipping: a job that runs nightly as root with the node mounted is exactly
// the workload nobody is watching.
func (r Resource) PodSpec() map[string]interface{} {
	switch {
	case templatedKinds[r.Kind]:
		if tmpl, ok := r.Spec["template"].(map[string]interface{}); ok {
			spec, _ := tmpl["spec"].(map[string]interface{})
			return spec
		}
	case r.Kind == "CronJob":
		job, ok := r.Spec["jobTemplate"].(map[string]interface{})
		if !ok {
			return nil
		}
		jobSpec, ok := job["spec"].(map[string]interface{})
		if !ok {
			return nil
		}
		if tmpl, ok := jobSpec["template"].(map[string]interface{}); ok {
			spec, _ := tmpl["spec"].(map[string]interface{})
			return spec
		}
	case r.Kind == "Pod":
		return r.Spec
	}
	return nil
}

// OwnedByAController reports whether a listed controller created this object.
//
// Bare pods are assessed; pods a Deployment or Job created are not, because
// they are that controller's pod template with a generated name. Reporting both
// is one finding twice, and the copy with the random suffix is the one that is
// gone by the time anybody reads the report.
func (r Resource) OwnedByAController() bool {
	for _, o := range r.Metadata.OwnerReferences {
		if controllerKinds[o.Kind] {
			return true
		}
	}
	return false
}

// LoadDir reads every YAML manifest in a directory (.yaml and .yml), including
// multi-document files and the List documents `kubectl get -o yaml` writes.
// Empty documents are skipped; anything else that fails to parse is an error,
// because silently ignoring a malformed manifest would understate the
// findings.
func LoadDir(dir string) ([]Resource, error) {
	var paths []string
	for _, ext := range []string{"*.yaml", "*.yml"} {
		found, err := filepath.Glob(filepath.Join(dir, ext))
		if err != nil {
			return nil, err
		}
		paths = append(paths, found...)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no .yaml or .yml manifests found in %s", dir)
	}

	var out []Resource
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		name := filepath.Base(p)
		dec := yaml.NewDecoder(f)
		for i := 0; ; i++ {
			var doc yaml.Node
			err := dec.Decode(&doc)
			if err == io.EOF {
				break
			}
			if err == nil {
				out, err = appendDocument(out, &doc, name)
			}
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("%s document %d: %w", name, i, err)
			}
		}
		f.Close()
	}
	return out, nil
}

// appendDocument adds one YAML document to rs: the resource itself, or the
// items of a List. A List is unpacked one level only. kubectl never nests
// them, so a nested one is not an export, and refusing it is better than
// either unpacking without bound or dropping what is inside.
func appendDocument(rs []Resource, doc *yaml.Node, source string) ([]Resource, error) {
	kind, items := kindAndItems(doc)
	if !isList(kind, items) {
		var r Resource
		if err := doc.Decode(&r); err != nil {
			return rs, err
		}
		if r.Kind == "" {
			return rs, nil
		}
		r.Source = source
		return append(rs, r), nil
	}

	if items == nil || items.Kind != yaml.SequenceNode {
		return rs, fmt.Errorf("%s has no list of items", kind)
	}
	for j, node := range items.Content {
		if itemKind, itemItems := kindAndItems(node); isList(itemKind, itemItems) {
			return rs, fmt.Errorf("%s item %d is itself a %s; stathe reads one level of List, as kubectl writes it", kind, j, itemKind)
		}
		var r Resource
		if err := node.Decode(&r); err != nil {
			return rs, fmt.Errorf("%s item %d: %w", kind, j, err)
		}
		if r.Kind == "" {
			continue
		}
		r.Source = source
		rs = append(rs, r)
	}
	return rs, nil
}

// kindAndItems reads the kind and the items node of a document without
// decoding the rest. yaml.v3 will not decode into a yaml.Node field from a
// node, so the mapping is walked by hand. Anything that is not a mapping has
// neither.
func kindAndItems(n *yaml.Node) (string, *yaml.Node) {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return "", nil
	}
	var kind string
	var items *yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch n.Content[i].Value {
		case "kind":
			if n.Content[i+1].Kind == yaml.ScalarNode {
				kind = n.Content[i+1].Value
			}
		case "items":
			items = n.Content[i+1]
		}
	}
	return kind, items
}

// isList matches kubectl's List and the typed lists the API returns
// (DeploymentList, ConfigMapList). A typed list needs its items to count as
// one: a custom resource can be called IPAllowList and be nothing of the kind.
func isList(kind string, items *yaml.Node) bool {
	if kind == "List" {
		return true
	}
	return strings.HasSuffix(kind, "List") && items != nil && items.Kind == yaml.SequenceNode
}
