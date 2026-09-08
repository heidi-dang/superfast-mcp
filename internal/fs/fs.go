package fs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Service struct {
	roots []string
}

func New(roots []string) *Service {
	abs := make([]string, 0, len(roots))
	for _, r := range roots {
		a, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		abs = append(abs, a)
	}
	return &Service{roots: abs}
}

func (s *Service) withinRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	for _, root := range s.roots {
		if abs == root || strings.HasPrefix(abs, root+string(os.PathSeparator)) {
			return abs, nil
		}
	}
	return "", fmt.Errorf("path %q is outside allowed roots", path)
}

type ReadFileArgs struct {
	Path string `json:"path" jsonschema:"absolute or root-relative path to read"`
}

type ReadFileOut struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Bytes   int    `json:"bytes"`
}

func (s *Service) ReadFile(ctx context.Context, req *mcp.CallToolRequest, args ReadFileArgs) (*mcp.CallToolResult, ReadFileOut, error) {
	abs, err := s.withinRoot(args.Path)
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, ReadFileOut{}, nil
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, ReadFileOut{}, nil
	}
	const max = 512 * 1024
	truncated := false
	if len(data) > max {
		data = data[:max]
		truncated = true
	}
	out := ReadFileOut{Path: abs, Content: string(data), Bytes: len(data)}
	text := fmt.Sprintf("Read %s (%d bytes)", abs, len(data))
	if truncated {
		text += " [truncated]"
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, out, nil
}

type WriteFileArgs struct {
	Path    string `json:"path" jsonschema:"path to write"`
	Content string `json:"content" jsonschema:"file content"`
}

type WriteFileOut struct {
	Path  string `json:"path"`
	Bytes int    `json:"bytes"`
}

func (s *Service) WriteFile(ctx context.Context, req *mcp.CallToolRequest, args WriteFileArgs) (*mcp.CallToolResult, WriteFileOut, error) {
	abs, err := s.withinRoot(args.Path)
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, WriteFileOut{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, WriteFileOut{}, nil
	}
	if err := os.WriteFile(abs, []byte(args.Content), 0o644); err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, WriteFileOut{}, nil
	}
	out := WriteFileOut{Path: abs, Bytes: len(args.Content)}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Wrote %s (%d bytes)", abs, len(args.Content))}},
	}, out, nil
}

type ListDirArgs struct {
	Path string `json:"path" jsonschema:"directory path"`
}

type ListDirOut struct {
	Path    string   `json:"path"`
	Entries []string `json:"entries"`
}

func (s *Service) ListDir(ctx context.Context, req *mcp.CallToolRequest, args ListDirArgs) (*mcp.CallToolResult, ListDirOut, error) {
	abs, err := s.withinRoot(args.Path)
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, ListDirOut{}, nil
	}
	ents, err := os.ReadDir(abs)
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, ListDirOut{}, nil
	}
	names := make([]string, 0, len(ents))
	for i, e := range ents {
		if i >= 500 {
			names = append(names, "...(truncated)")
			break
		}
		n := e.Name()
		if e.IsDir() {
			n += "/"
		}
		names = append(names, n)
	}
	out := ListDirOut{Path: abs, Entries: names}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s: %d entries", abs, len(names))}},
	}, out, nil
}

func (s *Service) Roots() []string {
	return append([]string(nil), s.roots...)
}
