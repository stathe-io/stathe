package scan

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
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

	Source string `yaml:"-"`
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

// LoadDir reads every YAML manifest in a directory, including multi-document
// files. Empty documents are skipped; anything else that fails to parse is an
// error, because silently ignoring a malformed manifest would understate the
// findings.
func LoadDir(dir string) ([]Resource, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no .yaml manifests found in %s", dir)
	}

	var out []Resource
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(f)
		for i := 0; ; i++ {
			var r Resource
			err := dec.Decode(&r)
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("%s document %d: %w", filepath.Base(p), i, err)
			}
			if r.Kind == "" {
				continue
			}
			r.Source = filepath.Base(p)
			out = append(out, r)
		}
		f.Close()
	}
	return out, nil
}
