package git

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Service struct {
	roots []string
}

func New(roots []string) *Service {
	return &Service{roots: roots}
}

func (s *Service) run(ctx context.Context, cwd string, args ...string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = cwd
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return stdout.String(), stderr.String(), code, err
}

type StatusArgs struct {
	Path string `json:"path,omitempty" jsonschema:"git repo path (defaults to first root)"`
}

type StatusOut struct {
	Path   string `json:"path"`
	Status string `json:"status"`
}

func (s *Service) Status(ctx context.Context, req *mcp.CallToolRequest, args StatusArgs) (*mcp.CallToolResult, StatusOut, error) {
	cwd := args.Path
	if cwd == "" && len(s.roots) > 0 {
		cwd = s.roots[0]
	}
	stdout, stderr, code, _ := s.run(ctx, cwd, "status", "--porcelain=v1", "-b")
	text := stdout
	if stderr != "" {
		text += "\n" + stderr
	}
	if code != 0 && text == "" {
		text = fmt.Sprintf("git status failed (exit %d)", code)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: code != 0,
	}, StatusOut{Path: cwd, Status: stdout}, nil
}

type DiffArgs struct {
	Path    string `json:"path,omitempty"`
	Staged  bool   `json:"staged,omitempty"`
	Context int    `json:"context,omitempty"`
}

type DiffOut struct {
	Path string `json:"path"`
	Diff string `json:"diff"`
}

func (s *Service) Diff(ctx context.Context, req *mcp.CallToolRequest, args DiffArgs) (*mcp.CallToolResult, DiffOut, error) {
	cwd := args.Path
	if cwd == "" && len(s.roots) > 0 {
		cwd = s.roots[0]
	}
	gitArgs := []string{"diff"}
	if args.Staged {
		gitArgs = append(gitArgs, "--cached")
	}
	if args.Context > 0 {
		gitArgs = append(gitArgs, fmt.Sprintf("-U%d", args.Context))
	}
	stdout, stderr, code, _ := s.run(ctx, cwd, gitArgs...)
	text := stdout
	if text == "" && code == 0 {
		text = "(no diff)"
	}
	if stderr != "" {
		text += "\n" + stderr
	}
	if len(text) > 100*1024 {
		text = text[:100*1024] + "\n...[truncated]"
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: code != 0,
	}, DiffOut{Path: cwd, Diff: stdout}, nil
}

type LogArgs struct {
	Path  string `json:"path,omitempty"`
	Limit int    `json:"limit,omitempty" jsonschema:"max commits (default 10)"`
}

type LogOut struct {
	Path string `json:"path"`
	Log  string `json:"log"`
}

func (s *Service) Log(ctx context.Context, req *mcp.CallToolRequest, args LogArgs) (*mcp.CallToolResult, LogOut, error) {
	cwd := args.Path
	if cwd == "" && len(s.roots) > 0 {
		cwd = s.roots[0]
	}
	n := args.Limit
	if n <= 0 {
		n = 10
	}
	if n > 50 {
		n = 50
	}
	stdout, stderr, code, _ := s.run(ctx, cwd, "log", fmt.Sprintf("-%d", n), "--oneline", "--decorate")
	text := strings.TrimSpace(stdout)
	if stderr != "" {
		text += "\n" + stderr
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: code != 0,
	}, LogOut{Path: cwd, Log: stdout}, nil
}
