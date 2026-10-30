package scan

import (
	"strings"
	"testing"
)

// A filter that cannot be seen in the output is the failure mode this whole
// file exists to prevent: a run that looked at less than the reader thinks and
// reports a smaller number without saying why.
func TestInventoryCountsWhatItSkips(t *testing.T) {
	inv := &Inventory{}
	for _, r := range []Resource{
		{Kind: "Deployment", Metadata: Metadata{Name: "shop", Namespace: "shop"}},
		{Kind: "Deployment", Metadata: Metadata{Name: "coredns", Namespace: "kube-system"}},
		{Kind: "ConfigMap", Metadata: Metadata{Name: "kubeadm", Namespace: "kube-system"}},
		{Kind: "ClusterRoleBinding", Metadata: Metadata{Name: "cluster-admin"}},
	} {
		inv.Add(r)
	}

	if len(inv.Resources) != 2 {
		t.Errorf("expected 2 resources kept (shop and the cluster-scoped binding), got %d", len(inv.Resources))
	}

	skipped := inv.Skipped()
	if len(skipped) != 1 {
		t.Fatalf("expected one skipped namespace, got %d", len(skipped))
	}
	if !strings.Contains(skipped[0].What, "2 resources in namespace kube-system") {
		t.Errorf("the count has to be in the output, got %q", skipped[0].What)
	}
	if skipped[0].Reason == "" {
		t.Error("a skipped namespace without a reason is as good as a silent one")
	}
}

func TestInventoryReportsNothingWhenNothingWasSkipped(t *testing.T) {
	inv := &Inventory{}
	inv.Add(Resource{Kind: "Deployment", Metadata: Metadata{Name: "shop", Namespace: "shop"}})

	if got := inv.Skipped(); len(got) != 0 {
		t.Errorf("expected no exclusions to report, got %d: %+v", len(got), got)
	}
}

func TestPlatformSubjectsExplainsWhatItLeftOut(t *testing.T) {
	rs := []Resource{{
		Kind:     "ClusterRoleBinding",
		Metadata: Metadata{Name: "cluster-admin"},
		RoleRef:  map[string]string{"name": "cluster-admin"},
		Subjects: []map[string]string{
			{"kind": "Group", "name": "system:masters"},
			{"kind": "ServiceAccount", "name": "runner", "namespace": "build"},
		},
	}}

	got := PlatformSubjects(rs)
	if len(got) != 1 {
		t.Fatalf("expected only system:masters to be accounted as suppressed, got %d: %+v", len(got), got)
	}
	if !strings.Contains(got[0].What, "system:masters") {
		t.Errorf("the suppressed subject has to be named, got %q", got[0].What)
	}
	if !strings.Contains(got[0].What, "clusterrolebinding/cluster-admin") {
		t.Errorf("the binding it came from has to be named so the reader can look it up, got %q", got[0].What)
	}
}

// The aggregate groups are the reason SC-06 no longer filters on the system:
// prefix. The report has to spell out what they cover, because "grants
// cluster-admin to group system:serviceaccounts:build" reads as narrow to
// anyone who does not know the group by heart.
func TestAggregateGroupsAreSpelledOut(t *testing.T) {
	tests := []struct {
		subject string
		want    string
	}{
		{"system:authenticated", "every user and workload"},
		{"system:unauthenticated", "anyone who can reach the API server"},
		{"system:anonymous", "anyone who can reach the API server"},
		{"system:serviceaccounts", "every service account in every namespace"},
		{"system:serviceaccounts:build", "every service account in namespace build"},
	}

	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			rs := []Resource{{
				Kind:     "ClusterRoleBinding",
				Metadata: Metadata{Name: "oops"},
				RoleRef:  map[string]string{"name": "cluster-admin"},
				Subjects: []map[string]string{{"kind": "Group", "name": tt.subject}},
			}}

			got := CheckClusterAdmin(rs)
			if len(got) != 1 {
				t.Fatalf("expected %s to be reported, got %d findings", tt.subject, len(got))
			}
			if !strings.Contains(got[0].Detail, tt.want) {
				t.Errorf("expected the detail to explain the group as %q, got %q", tt.want, got[0].Detail)
			}
		})
	}
}
