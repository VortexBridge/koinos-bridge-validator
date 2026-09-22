//go:build !linux
// +build !linux

package managed

import "errors"

func localHostBinding() (string, error) { return "", errors.New("managed host review requires Linux") }
