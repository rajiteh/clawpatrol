//go:build !linux

package main

import (
	"context"
	"fmt"
)

func tunModeRun(_ context.Context, _ tunModeOptions) error {
	return fmt.Errorf("run --tun is only supported on Linux")
}
