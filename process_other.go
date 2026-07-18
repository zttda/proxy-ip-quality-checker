//go:build !windows

package main

import (
	"context"
	"os/exec"
)

func managedCommand(ctx context.Context, executable string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, executable, args...)
}
