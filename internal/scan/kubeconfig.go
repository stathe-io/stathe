package scan

import (
	"fmt"
	"os"
	"strings"
)

// KubeconfigError turns a kubeconfig failure into something the reader can act
// on.
//
// The container case is the one that costs people an afternoon:
// `-v $HOME/.kube:/kube:ro` makes Docker create a root-owned empty directory
// when the source path does not exist, and KUBECONFIG then points at a
// directory. The library reports "is a directory", which is true and tells you
// nothing about which of the two mistakes you made.
func KubeconfigError(err error) error {
	msg := err.Error()

	switch {
	case strings.Contains(msg, "is a directory"):
		return fmt.Errorf("%w\n\n"+
			"KUBECONFIG points at a directory rather than a file.%s\n"+
			"  In a container, bind-mount the file itself and fail loudly if it is missing:\n"+
			"    docker run --rm \\\n"+
			"      --mount type=bind,src=$HOME/.kube/config,dst=/kube/config,readonly \\\n"+
			"      --user \"$(id -u):$(id -g)\" \\\n"+
			"      -e KUBECONFIG=/kube/config \\\n"+
			"      ghcr.io/stathe-io/stathe check\n"+
			"  With -v, Docker silently creates a root-owned empty directory when the\n"+
			"  source path does not exist, and this is what that looks like.",
			err, kubeconfigPathNote())

	case strings.Contains(msg, "permission denied"):
		return fmt.Errorf("%w\n\n"+
			"The kubeconfig cannot be read.%s\n"+
			"  A kubeconfig is usually mode 600, and the image runs as uid 65532, so add\n"+
			"  --user \"$(id -u):$(id -g)\" to the docker run.",
			err, kubeconfigPathNote())

	case strings.Contains(msg, "no configuration has been provided"),
		strings.Contains(msg, "no such file or directory"):
		return fmt.Errorf("%w\n\n"+
			"No kubeconfig was found.%s\n"+
			"  Set KUBECONFIG, or pass --manifests DIR to assess files instead of a cluster.",
			err, kubeconfigPathNote())
	}

	return fmt.Errorf("could not load kubeconfig: %w", err)
}

// kubeconfigPathNote names the path that was actually consulted. Guessing which
// of three mechanisms supplied it is exactly the confusion worth removing.
func kubeconfigPathNote() string {
	if p := os.Getenv("KUBECONFIG"); p != "" {
		return fmt.Sprintf("\n  KUBECONFIG=%s", p)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return fmt.Sprintf("\n  KUBECONFIG is not set, so the default was tried: %s/.kube/config", home)
	}
	return ""
}
