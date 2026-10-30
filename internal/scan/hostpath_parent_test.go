package scan

import (
	"strings"
	"testing"
)

// A mount of a parent directory grants everything the child grants and more.
// The ranking only ever compared downwards -- a path was judged by the listed
// entry it sat *beneath* -- so /etc/kubernetes ranked as control of the node
// while /etc, which contains it, fell through to "some other host mount".
//
// Longhorn mounts /etc, /proc, /dev, /boot and /var/lib/longhorn on one
// DaemonSet. stathe reported it as "mounts /dev, which exposes the node's
// processes", naming the least alarming of them while /etc carried the
// kubelet's credentials and the host's SSH keys. Understating it that
// precisely is worse than missing it: the reader checks /dev, finds it
// harmless, and stops believing the check.
func TestParentOfADangerousPathRanksAtLeastAsHigh(t *testing.T) {
	tests := []struct {
		path string
		want hostPathRank
		why  string
	}{
		// /etc contains /etc/kubernetes (control) and /etc/ssh (write).
		{"/etc", nodeControl, "contains the kubelet's credentials"},
		// /var/lib contains /var/lib/kubelet and /var/lib/containerd.
		{"/var/lib", nodeControl, "contains the kubelet's credentials"},
		// /var contains /var/lib/kubelet by way of /var/lib.
		{"/var", nodeControl, "contains the kubelet's credentials"},
		// /run contains /run/containerd, the runtime socket.
		{"/run", nodeControl, "contains the runtime socket"},
		// /home is already listed as a write path and must not regress.
		{"/home", nodeWrite, "decides who may log in"},
		// A leaf with nothing dangerous under it stays where it was.
		{"/var/lib/longhorn", hostPathOther, ""},
		{"/proc", nodeRead, "exposes the node"},
		{"/etc/kubernetes", nodeControl, "is control of the node"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, why := rankHostPath(tt.path)
			if got != tt.want {
				t.Errorf("rank of %s = %d, want %d (%s)", tt.path, got, tt.want, tt.why)
			}
			if tt.want != hostPathOther && why == "" {
				t.Errorf("%s was ranked but given no explanation, so the finding cannot say why", tt.path)
			}
		})
	}
}

// Whatever the parent rule does, the sentence has to name the path that was
// actually mounted. A finding that says "/etc/kubernetes" about a workload
// whose manifest says "/etc" sends the reader looking for a mount that is not
// there.
func TestTheExplanationNamesThePathThatWasMounted(t *testing.T) {
	_, why := rankHostPath("/etc")
	if !strings.HasPrefix(why, "/etc,") {
		t.Fatalf("the detail has to open with the path the manifest asked for, got %q", why)
	}
	// Naming the child afterwards is the point: it is the reason the mount
	// ranks where it does, and without it the reader cannot check the claim.
	// What must not happen is the child standing in place of the mount.
	if !strings.Contains(why, "contains /etc/kubernetes") {
		t.Errorf("the detail has to say what sits under the mount, got %q", why)
	}
}

// The worst path on a workload decides the risk, so the parent rule has to
// reach hostPathFinding and not just rankHostPath.
func TestWorstPathWinsWhenTheParentIsTheWorst(t *testing.T) {
	f, ok := hostPathFinding("longhorn-system/daemonset/longhorn-manager",
		[]string{"/dev", "/proc", "/etc", "/boot", "/var/lib/longhorn"})
	if !ok {
		t.Fatal("expected a finding")
	}
	if f.Risk != High {
		t.Errorf("a workload mounting all of /etc is high, got %s", f.Risk)
	}
	if !strings.Contains(f.Detail, "/etc") {
		t.Errorf("the worst path has to lead the detail, got %q", f.Detail)
	}
	if strings.HasPrefix(f.Detail, "mounts /dev") {
		t.Errorf("the detail still leads with the least alarming mount: %q", f.Detail)
	}
	if f.Cause != "/etc" {
		t.Errorf("Cause should be the worst path so findings group by it, got %q", f.Cause)
	}
}
