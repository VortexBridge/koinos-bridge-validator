package main

import (
	"strings"
	"testing"
)

func TestArgumentErrorsDoNotEchoInput(t *testing.T) {
	for _, args := range [][]string{{"--password=synthetic-secret"}, {"--passphrase-fd=synthetic-secret"}, {"synthetic-secret"}} {
		err := run(args)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("argument error echoed untrusted input")
		}
	}
}
