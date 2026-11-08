/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

// Package testutil locates the real haltsql CLI for tests.
package testutil

import (
	"os"
	"os/exec"
	"testing"
)

// HaltSQLBinary returns the haltsql CLI from $HALTSQL_BIN or $PATH. When
// neither has one it skips the test, or fails it when
// HALTSQL_REQUIRE_BINARY=1 (CI and `make test` set it).
func HaltSQLBinary(t testing.TB) string {
	t.Helper()
	if p := os.Getenv("HALTSQL_BIN"); p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("HALTSQL_BIN=%s: %v", p, err)
		}
		return p
	}
	if p, err := exec.LookPath("haltsql"); err == nil {
		return p
	}
	msg := "haltsql CLI not found: set HALTSQL_BIN (e.g. dune build ./bin/haltsql/main.exe) or put haltsql on PATH"
	if os.Getenv("HALTSQL_REQUIRE_BINARY") == "1" {
		t.Fatal(msg)
	}
	t.Skip(msg)
	return ""
}
