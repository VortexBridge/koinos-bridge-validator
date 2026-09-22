//go:build linux
// +build linux

package main

import (
	"os/exec"
	"syscall"
)

func protectChild(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM} }
