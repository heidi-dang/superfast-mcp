package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heidi-dang/superfast-mcp/internal/roots"
)

func newTestService(t *testing.T, root string) *Service {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	set, err := roots.New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	return New(set)
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestDiffBoundsStructuredOutput(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	file := filepath.Join(root, "large.txt")
	if err := os.WriteFile(file, []byte("baseline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "large.txt")
	if err := os.WriteFile(file, []byte(strings.Repeat("changed-line\n", 20000)), 0o644); err != nil {
		t.Fatal(err)
	}

	result, out, err := newTestService(t, root).Diff(context.Background(), nil, DiffArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected git diff error: %#v", result.Content)
	}
	if !strings.Contains(out.Diff, "...[truncated]") {
		t.Fatal("expected structured diff to be truncated")
	}
	if len(out.Diff) > 100*1024+32 {
		t.Fatalf("structured diff retained too much output: %d", len(out.Diff))
	}
}

func TestStatusRejectsPathOutsideRoots(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	result, _, err := newTestService(t, root).Status(context.Background(), nil, StatusArgs{Path: outside})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected git path outside roots to fail")
	}
}
