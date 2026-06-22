//go:build !linux

package main

import (
	"context"
	"fmt"
)

func agentRun(_ context.Context, _ agentOptions) error {
	return fmt.Errorf("run --tun is only supported on Linux")
}
