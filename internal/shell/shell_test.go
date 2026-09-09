package shell

import (
	"context"
	"strings"
	"testing"

	"github.com/heidi-dang/superfast-mcp/internal/roots"
)

func newTestService(t *testing.T, root string) *Service {
	t.Helper()
	set, err := roots.New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	return New(set)
}

func TestRunRejectsCwdOutsideRoots(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	result, _, err := newTestService(t, root).Run(context.Background(), nil, RunArgs{Command: "pwd", Cwd: outside})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected cwd escape to fail")
	}
}

func TestRunBoundsStdout(t *testing.T) {
	root := t.TempDir()
	result, out, err := newTestService(t, root).Run(context.Background(), nil, RunArgs{Command: "yes x | head -c 70000"})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected command failure: %#v", result.Content)
	}
	if !strings.Contains(out.Stdout, "...[truncated]") {
		t.Fatal("expected stdout truncation marker")
	}
	if len(out.Stdout) > 64*1024+32 {
		t.Fatalf("stdout retained too much data: %d", len(out.Stdout))
	}
}

func TestRunTimeoutIsReportedAsError(t *testing.T) {
	root := t.TempDir()
	result, out, err := newTestService(t, root).Run(context.Background(), nil, RunArgs{Command: "sleep 5", Timeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || !out.TimedOut || out.ExitCode != -1 {
		t.Fatalf("unexpected timeout result: isError=%v timedOut=%v exit=%d", result.IsError, out.TimedOut, out.ExitCode)
	}
}
