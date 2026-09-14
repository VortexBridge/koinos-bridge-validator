//go:build !linux
// +build !linux

package keyvault

func ReadSecret(fd int, prompt string) ([]byte, error) { return nil, ProtectProcess() }
