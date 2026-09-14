//go:build !linux
// +build !linux

package keyvault

import "errors"

func ProtectProcess() error {
	return errors.New("encrypted signing-key operations require the supported Linux host protections")
}
