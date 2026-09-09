package roots

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveRelativeAndRejectEscape(t *testing.T) {
	root := t.TempDir()
	set, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := set.Resolve(filepath.Join("nested", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(root, "nested", "file.txt")
	if resolved.Abs != want {
		t.Fatalf("resolved path = %q, want %q", resolved.Abs, want)
	}
	if _, err := set.Resolve(filepath.Join("..", "escape")); err == nil {
		t.Fatal("expected relative escape to be rejected")
	}
	outside := filepath.Join(filepath.Dir(root), "outside")
	if _, err := set.Resolve(outside); err == nil {
		t.Fatal("expected absolute escape to be rejected")
	}
}

func TestResolveExistingDirRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	set, err := New([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.ResolveExistingDir("escape"); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}
