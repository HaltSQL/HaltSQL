/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

package validate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ardada2468/HaltSQL/deploy/operator/internal/testutil"
)

const policy = `apiVersion: haltsql.dev/v1
kind: Policy
metadata:
  name: orders-agent
dialect: postgres
search_path: [app]
statements:
  allow: [select]
tables:
  app.orders:
    columns: [id, status]
`

func TestCLIValidate(t *testing.T) {
	v, err := NewCLI(testutil.HaltSQLBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := v.Validate(ctx, "policy.yaml", []byte(policy)); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	err = v.Validate(ctx, "policy.yaml", []byte(policy+"statementz: 1\n"))
	if !IsInvalid(err) {
		t.Fatalf("expected InvalidError, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "policy.yaml:12") || !strings.Contains(msg, "statementz") {
		t.Fatalf("error must be located: %q", msg)
	}
	if strings.Contains(msg, os.TempDir()) || strings.Contains(msg, "haltsql-validate-") {
		t.Fatalf("temp paths must not leak into messages: %q", msg)
	}
	jsonDoc := `{"apiVersion":"haltsql.dev/v1","kind":"Policy","metadata":{"name":"j"},"dialect":"postgres","statements":{"allow":["select"]}}`
	if err := v.Validate(ctx, "policy.json", []byte(jsonDoc)); err != nil {
		t.Fatalf("valid JSON policy rejected: %v", err)
	}
	// Placeholders are config-only: a policy may not read files.
	err = v.Validate(ctx, "policy.yaml", []byte(strings.Replace(policy, "orders-agent", "${file:/etc/hostname}", 1)))
	if !IsInvalid(err) {
		t.Fatalf("expected placeholder in policy to be invalid, got %v", err)
	}
}

func TestCLIValidateArguments(t *testing.T) {
	v, err := NewCLI(testutil.HaltSQLBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "../x.yaml", "a/b.yaml", ".hidden.yaml", "policy.txt"} {
		if err := v.Validate(context.Background(), name, []byte(policy)); err == nil || IsInvalid(err) {
			t.Errorf("name %q: expected an argument error, got %v", name, err)
		}
	}
}

func TestNewCLIRejectsNonExecutables(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewCLI(""); err == nil {
		t.Error("empty path accepted")
	}
	if _, err := NewCLI(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
	f := filepath.Join(dir, "plain")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCLI(f); err == nil {
		t.Error("non-executable accepted")
	}
	if _, err := NewCLI(dir); err == nil {
		t.Error("directory accepted")
	}
}

func TestOperationalErrorIsNotInvalid(t *testing.T) {
	// A binary that exits 2 (load/usage error) is an operational failure,
	// not a verdict on the document.
	dir := t.TempDir()
	script := filepath.Join(dir, "haltsql")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho boom >&2\nexit 2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	v, err := NewCLI(script)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Validate(context.Background(), "policy.yaml", []byte(policy))
	if err == nil || IsInvalid(err) || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected an operational error, got %v", err)
	}
}

func TestClean(t *testing.T) {
	long := strings.Repeat("é", maxOutput)
	got := clean(long, "/tmp/x")
	if len(got) > maxOutput+32 || !strings.HasSuffix(got, "(truncated)") {
		t.Fatalf("not truncated: %d", len(got))
	}
	if !strings.HasPrefix(clean("/tmp/x/policy.yaml:1:1: bad", "/tmp/x"), "policy.yaml:1:1") {
		t.Fatal("temp dir not stripped")
	}
}
