package fs

import (
	"context"
	"os"
	"path/filepath"
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

func TestReadFileSupportsRootRelativePathAndBoundsOutput(t *testing.T) {
	root := t.TempDir()
	content := strings.Repeat("x", maxReadBytes+100)
	if err := os.WriteFile(filepath.Join(root, "large.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result, out, err := newTestService(t, root).ReadFile(context.Background(), nil, ReadFileArgs{Path: "large.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %#v", result.Content)
	}
	if !out.Truncated || out.Bytes != maxReadBytes || len(out.Content) != maxReadBytes {
		t.Fatalf("unexpected bounded read: truncated=%v bytes=%d len=%d", out.Truncated, out.Bytes, len(out.Content))
	}
}

func TestFilesystemRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, root)

	readResult, _, err := service.ReadFile(context.Background(), nil, ReadFileArgs{Path: "escape/secret.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if !readResult.IsError {
		t.Fatal("expected read through escaping symlink to fail")
	}

	writeResult, _, err := service.WriteFile(context.Background(), nil, WriteFileArgs{Path: "escape/new.txt", Content: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if !writeResult.IsError {
		t.Fatal("expected write through escaping symlink to fail")
	}
	if _, err := os.Stat(filepath.Join(outside, "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside file was created, stat err=%v", err)
	}
}

func TestWriteFileRejectsOversizeContent(t *testing.T) {
	root := t.TempDir()
	result, _, err := newTestService(t, root).WriteFile(context.Background(), nil, WriteFileArgs{
		Path:    "too-large.txt",
		Content: strings.Repeat("x", maxWriteBytes+1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected oversized write to fail")
	}
}
