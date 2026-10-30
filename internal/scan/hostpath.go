package scan

import (
	"fmt"
	"sort"
	"strings"
)

// Host paths are not one finding repeated. A mounted container runtime socket
// is control of the node and everything scheduled on it: whoever reaches that
// container can start a privileged container of their own, and no RBAC in the
// cluster applies. A read-only /usr is a different conversation.
//
// Reporting both at high, one line each, puts the reader in the position of
// ranking them -- which is the work stathe is supposed to have done.

// hostPathRank is how much a mounted host path is worth to an attacker.
type hostPathRank int

const (
	// nodeControl is the container runtime socket or the kubelet's own
	// credentials: a direct path to running anything on the node.
	nodeControl hostPathRank = iota
	// nodeWrite is a path that lets someone change what the node runs next.
	nodeWrite
	// nodeRead exposes the node's contents without an obvious write.
	nodeRead
	// hostPathOther is any other host mount: still outside the container, but
	// stathe will not pretend to know what it holds.
	hostPathOther
)

// runtimeSockets are the paths that mean control of the node. The list covers
// the distributions rather than just Docker: on RKE2 and k3s the socket lives
// under /run/k3s or /var/lib/rancher, and a check that only knew
// /var/run/docker.sock would have called those "some host mount".
var runtimeSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/containerd",
	"/run/containerd",
	"/run/crio",
	"/var/run/crio",
	"/run/k3s/containerd",
	"/var/lib/rancher/rke2/agent/containerd",
	"/var/lib/kubelet",
	"/var/lib/docker",
	"/var/lib/containerd",
	"/etc/kubernetes",
	"/var/lib/rancher/rke2/server",
}

// nodeWritePaths let someone change what the node runs or who may reach it.
var nodeWritePaths = []string{
	"/etc/systemd",
	"/lib/systemd",
	"/usr/lib/systemd",
	"/etc/cron.d",
	"/etc/crontab",
	"/root",
	"/home",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/ssh",
	"/var/lib/cloud",
}

// nodeReadPaths expose the node without an obvious write.
var nodeReadPaths = []string{
	"/proc",
	"/sys",
	"/dev",
	"/var/log",
	"/etc/shadow",
	"/etc/passwd",
}

// rankHostPath judges one host path. The whole node ("/") outranks everything,
// because it contains every path below.
func rankHostPath(path string) (hostPathRank, string) {
	p := strings.TrimRight(strings.TrimSpace(path), "/")
	if p == "" {
		return nodeControl, "the entire node filesystem, which includes the container runtime socket and the kubelet's credentials"
	}

	if match, ok := underAny(p, runtimeSockets); ok {
		return nodeControl, fmt.Sprintf("%s, which is control of the node: "+
			"anything there can start a privileged container that no cluster RBAC applies to", match)
	}
	if match, ok := underAny(p, nodeWritePaths); ok {
		return nodeWrite, fmt.Sprintf("%s, which decides what the node runs or who may log into it", match)
	}
	if match, ok := underAny(p, nodeReadPaths); ok {
		return nodeRead, fmt.Sprintf("%s, which exposes the node's processes, devices or logs", match)
	}
	return hostPathOther, ""
}

// underAny reports whether a path is one of the listed paths or sits beneath
// one, and returns the entry that matched so the detail can name it.
func underAny(path string, list []string) (string, bool) {
	for _, candidate := range list {
		if path == candidate || strings.HasPrefix(path, candidate+"/") {
			return candidate, true
		}
	}
	return "", false
}

// hostPathFinding turns every host mount on one workload into a single
// finding, worded around the worst of them.
//
// One line per path reads as several problems and is one: a workload with the
// runtime socket, /proc and /var/log mounted has exactly one thing wrong with
// it. The risk follows the worst path, and the rest are listed so nobody has
// to go and look them up.
func hostPathFinding(ref string, paths []string) (Finding, bool) {
	if len(paths) == 0 {
		return Finding{}, false
	}

	sort.Strings(paths)

	worstRank := hostPathOther
	worst, worstWhy := "", ""
	for _, p := range paths {
		rank, why := rankHostPath(p)
		if rank < worstRank || worst == "" {
			worstRank, worst, worstWhy = rank, p, why
		}
	}

	risk := Medium
	if worstRank <= nodeWrite {
		risk = High
	}

	detail := "mounts the node filesystem at " + worst
	if worstWhy != "" {
		detail = "mounts " + worstWhy
	}
	if len(paths) > 1 {
		others := make([]string, 0, len(paths)-1)
		for _, p := range paths {
			if p != worst {
				others = append(others, p)
			}
		}
		detail += fmt.Sprintf(" (and %s: %s)", plural(len(others), "other host mount"), strings.Join(others, ", "))
	}

	f := finding("SC-05", ref, detail, risk)
	// The worst path is what the findings on different workloads have in
	// common when a chart mounts the same socket everywhere.
	f.Cause = worst
	return f, true
}
