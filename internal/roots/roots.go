package roots

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Resolved identifies a path relative to one configured workspace root.
type Resolved struct {
	Root string
	Rel  string
	Abs  string
}

// Set holds canonical workspace roots and resolves user-supplied paths against them.
type Set struct {
	roots []string
}

func New(paths []string) (*Set, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one workspace root is required")
	}

	seen := make(map[string]struct{}, len(paths))
	roots := make([]string, 0, len(paths))
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve root %q: %w", path, err)
		}
		canonical, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, fmt.Errorf("resolve root %q: %w", path, err)
		}
		info, err := os.Stat(canonical)
		if err != nil {
			return nil, fmt.Errorf("stat root %q: %w", path, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("root %q is not a directory", path)
		}
		canonical = filepath.Clean(canonical)
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		roots = append(roots, canonical)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("at least one valid workspace root is required")
	}
	return &Set{roots: roots}, nil
}

func (s *Set) Paths() []string {
	return append([]string(nil), s.roots...)
}

// Resolve accepts an absolute path under any configured root or a path relative
// to the first configured root. It performs lexical containment only; filesystem
// operations should use os.Root to remain safe in the presence of symlinks.
func (s *Set) Resolve(path string) (Resolved, error) {
	if len(s.roots) == 0 {
		return Resolved{}, fmt.Errorf("no workspace roots configured")
	}

	if path == "" {
		return Resolved{Root: s.roots[0], Rel: ".", Abs: s.roots[0]}, nil
	}

	if !filepath.IsAbs(path) {
		rel := filepath.Clean(path)
		if escapes(rel) {
			return Resolved{}, fmt.Errorf("path %q is outside allowed roots", path)
		}
		return Resolved{
			Root: s.roots[0],
			Rel:  rel,
			Abs:  filepath.Join(s.roots[0], rel),
		}, nil
	}

	abs := filepath.Clean(path)
	for _, root := range s.roots {
		rel, err := filepath.Rel(root, abs)
		if err != nil || escapes(rel) {
			continue
		}
		return Resolved{Root: root, Rel: rel, Abs: abs}, nil
	}
	return Resolved{}, fmt.Errorf("path %q is outside allowed roots", path)
}

// ResolveExistingDir resolves path and verifies that its final symlink target is
// an existing directory that remains inside the configured root.
func (s *Set) ResolveExistingDir(path string) (string, error) {
	resolved, err := s.Resolve(path)
	if err != nil {
		return "", err
	}

	root, err := os.OpenRoot(resolved.Root)
	if err != nil {
		return "", fmt.Errorf("open root %q: %w", resolved.Root, err)
	}
	defer root.Close()

	info, err := root.Stat(resolved.Rel)
	if err != nil {
		return "", fmt.Errorf("resolve directory %q: %w", path, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path %q is not a directory", path)
	}

	canonical, err := filepath.EvalSymlinks(resolved.Abs)
	if err != nil {
		return "", fmt.Errorf("resolve directory %q: %w", path, err)
	}
	if !within(resolved.Root, canonical) {
		return "", fmt.Errorf("path %q is outside allowed roots", path)
	}
	return canonical, nil
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && !escapes(rel)
}

func escapes(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
