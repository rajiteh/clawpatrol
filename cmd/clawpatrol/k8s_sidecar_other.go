//go:build !linux

package main

import (
	"fmt"
	"os"
)

func runK8sSidecar(args []string) {
	_ = args
	fmt.Fprintln(os.Stderr, "clawpatrol k8s-sidecar is only supported on Linux")
	os.Exit(2)
}
