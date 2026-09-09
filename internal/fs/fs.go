package fs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/heidi-dang/superfast-mcp/internal/roots"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxReadBytes  = 512 * 1024
	maxWriteBytes = 2 * 1024 * 1024
	maxDirEntries = 500
)

type Service struct {
	roots *roots.Set
}

func New(rootSet *roots.Set) *Service {
	return &Service{roots: rootSet}
}

type ReadFileArgs struct {
	Path string `json:"path" jsonschema:"absolute path under a configured root, or path relative to the first root"`
}

type ReadFileOut struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

func (s *Service) ReadFile(ctx context.Context, req *mcp.CallToolRequest, args ReadFileArgs) (*mcp.CallToolResult, ReadFileOut, error) {
	resolved, err := s.roots.Resolve(args.Path)
	if err != nil {
		return toolError(err), ReadFileOut{}, nil
	}
	root, err := os.OpenRoot(resolved.Root)
	if err != nil {
		return toolError(err), ReadFileOut{}, nil
	}
	defer root.Close()

	info, err := root.Stat(resolved.Rel)
	if err != nil {
		return toolError(err), ReadFileOut{}, nil
	}
	if !info.Mode().IsRegular() {
		return toolError(fmt.Errorf("path %q is not a regular file", args.Path)), ReadFileOut{}, nil
	}

	file, err := root.Open(resolved.Rel)
	if err != nil {
		return toolError(err), ReadFileOut{}, nil
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxReadBytes+1))
	if err != nil {
		return toolError(err), ReadFileOut{}, nil
	}
	truncated := len(data) > maxReadBytes
	if truncated {
		data = data[:maxReadBytes]
	}
	out := ReadFileOut{Path: resolved.Abs, Content: string(data), Bytes: len(data), Truncated: truncated}
	text := fmt.Sprintf("Read %s (%d bytes)", resolved.Abs, len(data))
	if truncated {
		text += " [truncated]"
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

type WriteFileArgs struct {
	Path    string `json:"path" jsonschema:"absolute path under a configured root, or path relative to the first root"`
	Content string `json:"content" jsonschema:"file content (max 2 MiB)"`
}

type WriteFileOut struct {
	Path  string `json:"path"`
	Bytes int    `json:"bytes"`
}

func (s *Service) WriteFile(ctx context.Context, req *mcp.CallToolRequest, args WriteFileArgs) (*mcp.CallToolResult, WriteFileOut, error) {
	if len(args.Content) > maxWriteBytes {
		return toolError(fmt.Errorf("content exceeds %d-byte write limit", maxWriteBytes)), WriteFileOut{}, nil
	}
	resolved, err := s.roots.Resolve(args.Path)
	if err != nil {
		return toolError(err), WriteFileOut{}, nil
	}
	root, err := os.OpenRoot(resolved.Root)
	if err != nil {
		return toolError(err), WriteFileOut{}, nil
	}
	defer root.Close()

	parent := filepath.Dir(resolved.Rel)
	if parent != "." {
		if err := root.MkdirAll(parent, 0o755); err != nil {
			return toolError(err), WriteFileOut{}, nil
		}
	}
	if err := root.WriteFile(resolved.Rel, []byte(args.Content), 0o644); err != nil {
		return toolError(err), WriteFileOut{}, nil
	}
	out := WriteFileOut{Path: resolved.Abs, Bytes: len(args.Content)}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Wrote %s (%d bytes)", resolved.Abs, len(args.Content))}}}, out, nil
}

type ListDirArgs struct {
	Path string `json:"path" jsonschema:"absolute directory under a configured root, or path relative to the first root"`
}

type ListDirOut struct {
	Path      string   `json:"path"`
	Entries   []string `json:"entries"`
	Truncated bool     `json:"truncated"`
}

func (s *Service) ListDir(ctx context.Context, req *mcp.CallToolRequest, args ListDirArgs) (*mcp.CallToolResult, ListDirOut, error) {
	resolved, err := s.roots.Resolve(args.Path)
	if err != nil {
		return toolError(err), ListDirOut{}, nil
	}
	root, err := os.OpenRoot(resolved.Root)
	if err != nil {
		return toolError(err), ListDirOut{}, nil
	}
	defer root.Close()

	dir, err := root.Open(resolved.Rel)
	if err != nil {
		return toolError(err), ListDirOut{}, nil
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return toolError(err), ListDirOut{}, nil
	}
	if !info.IsDir() {
		return toolError(fmt.Errorf("path %q is not a directory", args.Path)), ListDirOut{}, nil
	}

	entries, err := dir.ReadDir(maxDirEntries + 1)
	if err != nil && err != io.EOF {
		return toolError(err), ListDirOut{}, nil
	}
	truncated := len(entries) > maxDirEntries
	if truncated {
		entries = entries[:maxDirEntries]
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		names = append(names, name)
	}
	out := ListDirOut{Path: resolved.Abs, Entries: names, Truncated: truncated}
	text := fmt.Sprintf("%s: %d entries", resolved.Abs, len(names))
	if truncated {
		text += " [truncated]"
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

func (s *Service) Roots() []string {
	return s.roots.Paths()
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}
}
