//go:build windows

package main

import (
	"context"
	"os/exec"
	"strconv"
	"syscall"
)

func managedCommand(ctx context.Context, executable string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x00000200, // CREATE_NEW_PROCESS_GROUP
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		killer := exec.Command("taskkill.exe", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F")
		killer.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := killer.Run(); err != nil && cmd.ProcessState == nil {
			killErr := cmd.Process.Kill()
			if killErr != nil {
				return killErr
			}
		}
		return nil
	}
	return cmd
}
