/*
Copyright The HaltSQL Authors.

SPDX-License-Identifier: MIT
*/

// Package validate checks HaltSQL documents by running the real
// `haltsql validate` command, so the operator applies exactly the loader
// rules haltsql-server applies (unknown keys, ranges, references).
package validate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// maxOutput bounds the validator output copied into status messages.
const maxOutput = 4096

// InvalidError reports a document that `haltsql validate` rejected
// (exit code 1). Message holds the located errors.
type InvalidError struct {
	Message string
}

func (e *InvalidError) Error() string { return e.Message }

// IsInvalid reports whether err is an *InvalidError.
func IsInvalid(err error) bool {
	var ie *InvalidError
	return errors.As(err, &ie)
}

// Validator checks one document. Implementations must be safe for
// concurrent use.
type Validator interface {
	// Validate checks content. name is the file name shown in error messages
	// and its extension (.yaml or .json) selects the format. It returns nil
	// when the document is valid, an *InvalidError when it is not, and any
	// other error when the check itself could not run.
	Validate(ctx context.Context, name string, content []byte) error
}

// CLI runs `<Path> validate FILE` in a private temporary directory.
type CLI struct {
	// Path to the haltsql binary.
	Path string
	// Timeout for one run (default 20s).
	Timeout time.Duration
}

// NewCLI returns a CLI validator, checking that path is an executable file.
func NewCLI(path string) (*CLI, error) {
	if path == "" {
		return nil, errors.New("haltsql binary path is empty")
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("haltsql binary: %w", err)
	}
	if st.IsDir() || st.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("haltsql binary %q is not an executable file", path)
	}
	return &CLI{Path: path, Timeout: 20 * time.Second}, nil
}

// Validate implements Validator.
func (c *CLI) Validate(ctx context.Context, name string, content []byte) error {
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid document name %q", name)
	}
	ext := filepath.Ext(name)
	if ext != ".yaml" && ext != ".json" {
		return fmt.Errorf("document name %q must end in .yaml or .json", name)
	}
	dir, err := os.MkdirTemp("", "haltsql-validate-")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, content, 0o600); err != nil {
		return fmt.Errorf("writing document: %w", err)
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Path, "validate", file)
	cmd.Dir = dir
	// A minimal environment: no HALTSQL_* overrides and no secrets reach the
	// validator, and relative paths cannot escape the temp dir by accident.
	cmd.Env = []string{"HOME=" + dir, "TMPDIR=" + dir, "PATH=/usr/bin:/bin"}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	text := clean(out.String(), dir)
	if runErr == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("haltsql validate timed out after %s", timeout)
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) && ee.ExitCode() == 1 {
		if text == "" {
			text = name + ": invalid"
		}
		return &InvalidError{Message: text}
	}
	if text != "" {
		return fmt.Errorf("haltsql validate failed: %v: %s", runErr, text)
	}
	return fmt.Errorf("haltsql validate failed: %w", runErr)
}

// clean removes the temp dir from paths, collapses whitespace runs per line
// and bounds the length.
func clean(s, dir string) string {
	s = strings.ReplaceAll(s, dir+string(filepath.Separator), "")
	s = strings.ReplaceAll(s, dir, ".")
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	s = strings.Join(lines, "\n")
	if len(s) > maxOutput {
		s = strings.ToValidUTF8(s[:maxOutput], "") + "\n... (truncated)"
	}
	return s
}
