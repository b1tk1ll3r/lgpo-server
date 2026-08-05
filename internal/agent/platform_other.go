//go:build !windows

package agent

import (
	"context"
	"errors"
)

var errWindowsOnly = errors.New("policy application is supported only on Windows")

func backupLocalPolicy(context.Context, string, string) error        { return errWindowsOnly }
func applyPolicyDirectories(context.Context, string, []string) error { return errWindowsOnly }
func restoreLocalPolicy(context.Context, string, string) error       { return errWindowsOnly }
