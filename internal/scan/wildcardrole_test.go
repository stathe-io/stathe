package scan

import (
	"strings"
	"testing"
)

// Nobody binds a service account to cluster-admin in a cluster that gets
// reviewed. They write a ClusterRole with wildcards, name it after the
// component, and bind that -- which grants exactly the same thing and reads as
// ordinary platform plumbing.
//
// Argo CD ships this shape upstream (argocd-application-controller), so it is
// not a hypothetical: it is in one of the most widely deployed tools in the
// market stathe is aimed at. Matching on the name "cluster-admin" sees none of
// it, which is the difference between finding the obvious mistake and finding
// the real one.
func TestClusterAdminByAnyOtherName(t *testing.T) {
	rs := []Resource{
		{
			Kind:     "ClusterRole",
			Metadata: Metadata{Name: "platform-controller"},
			Rules: []PolicyRule{
				{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
			},
		},
		{
			Kind:     "ClusterRoleBinding",
			Metadata: Metadata{Name: "platform-controller"},
			RoleRef:  map[string]string{"kind": "ClusterRole", "name": "platform-controller"},
			Subjects: []map[string]string{
				{"kind": "ServiceAccount", "name": "controller", "namespace": "platform"},
			},
		},
	}

	got := CheckClusterAdmin(rs)
	if len(got) != 1 {
		t.Fatalf("expected the wildcard ClusterRole to be reported, got %d findings", len(got))
	}
	if got[0].Risk != High {
		t.Errorf("full control of the cluster is high, got %s", got[0].Risk)
	}
	// The reader has to be told why a role they do not recognise is as bad as
	// cluster-admin, or the finding reads as a false positive and gets closed.
	if !strings.Contains(got[0].Detail, "platform-controller") {
		t.Errorf("the role has to be named so it can be looked up, got %q", got[0].Detail)
	}
	if !strings.Contains(got[0].Detail, "every action on every resource") {
		t.Errorf("the detail has to spell out what the wildcards mean, got %q", got[0].Detail)
	}
}

// A broad role is not the same as an unlimited one. A controller that may do
// anything to Deployments is a different conversation from one that may do
// anything to anything, and reporting both at high teaches the reader to
// ignore the check.
func TestBroadButBoundedRoleIsNotReported(t *testing.T) {
	rs := []Resource{
		{
			Kind:     "ClusterRole",
			Metadata: Metadata{Name: "deployment-manager"},
			Rules: []PolicyRule{
				{APIGroups: []string{"apps"}, Resources: []string{"*"}, Verbs: []string{"*"}},
				{APIGroups: []string{""}, Resources: []string{"pods", "pods/log"}, Verbs: []string{"get", "list"}},
			},
		},
		{
			Kind:     "ClusterRoleBinding",
			Metadata: Metadata{Name: "deployment-manager"},
			RoleRef:  map[string]string{"kind": "ClusterRole", "name": "deployment-manager"},
			Subjects: []map[string]string{
				{"kind": "ServiceAccount", "name": "deployer", "namespace": "ci"},
			},
		},
	}

	if got := CheckClusterAdmin(rs); len(got) != 0 {
		t.Errorf("a role bounded to one apiGroup is not cluster-admin, got %d findings: %+v", len(got), got)
	}
}

// The wildcards have to line up on the same rule. Permission to read every
// resource, plus permission to do everything to one of them, is not permission
// to do everything to everything -- and a check that ORs the three fields
// together would call it that.
func TestWildcardsOnSeparateRulesAreNotClusterAdmin(t *testing.T) {
	rs := []Resource{
		{
			Kind:     "ClusterRole",
			Metadata: Metadata{Name: "reader-plus"},
			Rules: []PolicyRule{
				{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get", "list", "watch"}},
				{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"*"}},
			},
		},
		{
			Kind:     "ClusterRoleBinding",
			Metadata: Metadata{Name: "reader-plus"},
			RoleRef:  map[string]string{"kind": "ClusterRole", "name": "reader-plus"},
			Subjects: []map[string]string{
				{"kind": "ServiceAccount", "name": "watcher", "namespace": "ops"},
			},
		},
	}

	if got := CheckClusterAdmin(rs); len(got) != 0 {
		t.Errorf("wildcards spread over separate rules are not cluster-admin, got %d findings: %+v", len(got), got)
	}
}

// A binding whose ClusterRole is not in what was assessed cannot be judged.
// Guessing in either direction is wrong: calling it safe hides a real one, and
// calling it cluster-admin invents a finding about a role nobody can look up.
func TestUnresolvableRoleIsNotGuessedAt(t *testing.T) {
	rs := []Resource{{
		Kind:     "ClusterRoleBinding",
		Metadata: Metadata{Name: "mystery"},
		RoleRef:  map[string]string{"kind": "ClusterRole", "name": "some-role-we-never-saw"},
		Subjects: []map[string]string{
			{"kind": "ServiceAccount", "name": "app", "namespace": "shop"},
		},
	}}

	if got := CheckClusterAdmin(rs); len(got) != 0 {
		t.Errorf("an unresolvable role must not be reported as cluster-admin, got %+v", got)
	}
}

// The platform's own identities are suppressed on the name of the subject, and
// that has to keep working when the role is a wildcard one rather than
// literally cluster-admin.
func TestPlatformSubjectsStaySuppressedOnWildcardRoles(t *testing.T) {
	rs := []Resource{
		{
			Kind:     "ClusterRole",
			Metadata: Metadata{Name: "node-controller"},
			Rules: []PolicyRule{
				{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
			},
		},
		{
			Kind:     "ClusterRoleBinding",
			Metadata: Metadata{Name: "node-controller"},
			RoleRef:  map[string]string{"kind": "ClusterRole", "name": "node-controller"},
			Subjects: []map[string]string{
				{"kind": "Group", "name": "system:masters"},
			},
		},
	}

	if got := CheckClusterAdmin(rs); len(got) != 0 {
		t.Errorf("system:masters is the platform's own, got %d findings: %+v", len(got), got)
	}
}
