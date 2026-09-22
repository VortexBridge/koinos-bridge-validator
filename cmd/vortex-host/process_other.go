//go:build !linux
// +build !linux

package main

import "os/exec"

func protectChild(cmd *exec.Cmd) {}
