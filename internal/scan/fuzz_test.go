package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadDir feeds arbitrary bytes to the manifest loader and then runs every
// check over whatever it accepted.
//
// stathe is pointed at manifests from places its operator does not control: a
// client's repository, a pull request. The loader may reject input, and it may
// return an error, but it must never panic, hang or hand the checks a shape
// they cannot survive. The checks read loosely typed maps on purpose, which is
// exactly where an unchecked type assertion would hide.
func FuzzLoadDir(f *testing.F) {
	f.Add([]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n  namespace: b\ndata:\n  k: v\n"))
	f.Add([]byte("---\n---\nkind: Deployment\nspec: [\n"))
	f.Add([]byte("kind: Deployment\nmetadata: {name: a, namespace: b}\nspec:\n  template:\n    spec:\n      containers: [1, \"x\", {securityContext: 7, image: 3}]\n"))
	f.Add([]byte("kind: ClusterRoleBinding\nroleRef: {name: cluster-admin}\nsubjects: [1, {kind: 2}, null]\n"))
	f.Add([]byte("a: &a [*a]\n"))
	f.Add([]byte("kind: List\nitems: [1, null, {kind: List, items: [{kind: ConfigMap}]}, {kind: Deployment, spec: 3}]\n"))
	f.Add([]byte("kind: PodList\nitems: {kind: Pod}\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "m.yaml"), data, 0o600); err != nil {
			t.Fatal(err)
		}

		rs, err := LoadDir(dir)
		if err != nil {
			return
		}
		Run(rs)
	})
}
