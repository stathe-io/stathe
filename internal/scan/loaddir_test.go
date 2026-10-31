package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// `kubectl get deploy,cm -o yaml` writes one document of kind List with the
// objects under items. It is the first thing a client sends when asked for
// their manifests, and reading it as a single resource with no spec turned a
// privileged Deployment into "No findings".
func TestKubectlListExportIsAssessed(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "export.yaml", `apiVersion: v1
kind: List
items:
- apiVersion: apps/v1
  kind: Deployment
  metadata: {name: web, namespace: shop}
  spec:
    template:
      spec:
        containers:
        - name: web
          image: nginx:1.27
          securityContext: {privileged: true}
- apiVersion: v1
  kind: ConfigMap
  metadata: {name: settings, namespace: shop}
  data: {DB_PASSWORD: x}
metadata:
  resourceVersion: ""
`)

	rs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, r := range rs {
		kinds = append(kinds, r.Kind)
		if r.Source != "export.yaml" {
			t.Errorf("an item keeps the file it came from, got %q", r.Source)
		}
	}
	if strings.Join(kinds, ",") != "Deployment,ConfigMap" {
		t.Fatalf("the List has to be unpacked into its items, got %v", kinds)
	}

	got := map[string]bool{}
	for _, f := range Run(rs) {
		got[f.ID] = true
	}
	for _, id := range []string{"SC-04", "SC-05"} {
		if !got[id] {
			t.Errorf("expected %s from the unpacked items", id)
		}
	}
}

// The API returns typed lists too (DeploymentList, ConfigMapList) when a
// client saves a raw response; they carry items the same way.
func TestTypedListIsUnpacked(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "cms.yaml", `kind: ConfigMapList
items:
- kind: ConfigMap
  metadata: {name: a, namespace: b}
  data: {API_TOKEN: x}
`)
	rs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Kind != "ConfigMap" {
		t.Fatalf("expected the one ConfigMap, got %+v", rs)
	}
}

// kubectl never nests a List in a List. A file that does is not an export,
// and unpacking it recursively is a way to make the loader do unbounded work;
// refusing it with the file name is the honest answer.
func TestNestedListIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "nested.yaml", `kind: List
items:
- kind: List
  items:
  - kind: ConfigMap
    metadata: {name: a, namespace: b}
`)
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("a List inside a List has to be refused, not unpacked or dropped")
	}
	if !strings.Contains(err.Error(), "nested.yaml") {
		t.Errorf("the error has to name the file, got %v", err)
	}
}

// .yml is as common as .yaml in the repositories stathe is pointed at. Reading
// only one of them made half a directory disappear without a word, as long as
// at least one .yaml file was there to keep the "no manifests" error quiet.
func TestYmlIsRead(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "a.yaml", "kind: ConfigMap\nmetadata: {name: a, namespace: b}\n")
	writeManifest(t, dir, "b.yml", "kind: ConfigMap\nmetadata: {name: b, namespace: b}\n")

	rs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("expected both files to be read, got %d resources", len(rs))
	}
}

// A custom resource can end in "List" and still be one object. Unpacking it
// would drop it; it has no items, so it is read as itself.
func TestKindEndingInListWithoutItemsIsOneResource(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "allow.yaml", "kind: IPAllowList\nmetadata: {name: a, namespace: b}\nspec: {cidrs: [10.0.0.0/8]}\n")
	rs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Kind != "IPAllowList" {
		t.Fatalf("expected the custom resource as itself, got %+v", rs)
	}
}
