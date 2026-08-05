//go:build windows

package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func backupLocalPolicy(ctx context.Context, lgpoPath, destination string) error {
	if _, err := os.Stat(lgpoPath); err != nil {
		return fmt.Errorf("LGPO.exe not found: %w", err)
	}
	return runCommand(ctx, lgpoPath, "/q", "/b", destination, "/n", "GPO Distributor pre-apply rollback")
}

func applyPolicyDirectories(ctx context.Context, lgpoPath string, directories []string) error {
	for _, dir := range directories {
		if err := runCommand(ctx, lgpoPath, "/q", "/g", dir); err != nil {
			return err
		}
	}
	return runCommand(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "gpupdate.exe"), "/force", "/wait:600")
}

func restoreLocalPolicy(ctx context.Context, lgpoPath, rollbackRoot string) error {
	if err := runCommand(ctx, lgpoPath, "/q", "/g", rollbackRoot); err != nil {
		return err
	}
	return runCommand(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "gpupdate.exe"), "/force", "/wait:600")
}

func runCommand(ctx context.Context, program string, args ...string) error {
	cmd := exec.CommandContext(ctx, program, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s failed: %w: %s", program, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}
