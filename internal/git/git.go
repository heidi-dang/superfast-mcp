package git

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/heidi-dang/superfast-mcp/internal/limitio"
	"github.com/heidi-dang/superfast-mcp/internal/roots"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Service struct {
	roots *roots.Set
}

func New(rootSet *roots.Set) *Service {
	return &Service{roots: rootSet}
}

func (s *Service) run(ctx context.Context, path string, stdoutLimit int, args ...string) (string, string, string, int) {
	cwd, err := s.roots.ResolveExistingDir(path)
	if err != nil {
		return "", err.Error(), "", -1
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = cwd
	stdout := limitio.NewBuffer(stdoutLimit)
	stderr := limitio.NewBuffer(32 * 1024)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		code = -1
		if stderr.String() == "" {
			return stdout.String(), "git command timed out", cwd, code
		}
	}
	return stdout.String(), stderr.String(), cwd, code
}

type StatusArgs struct {
	Path string `json:"path,omitempty" jsonschema:"git repo path (defaults to first root)"`
}

type StatusOut struct {
	Path   string `json:"path"`
	Status string `json:"status"`
}

func (s *Service) Status(ctx context.Context, req *mcp.CallToolRequest, args StatusArgs) (*mcp.CallToolResult, StatusOut, error) {
	stdout, stderr, cwd, code := s.run(ctx, args.Path, 64*1024, "status", "--porcelain=v1", "-b")
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
	gitArgs := []string{"diff"}
	if args.Staged {
		gitArgs = append(gitArgs, "--cached")
	}
	if args.Context > 0 {
		contextLines := args.Context
		if contextLines > 100 {
			contextLines = 100
		}
		gitArgs = append(gitArgs, fmt.Sprintf("-U%d", contextLines))
	}
	stdout, stderr, cwd, code := s.run(ctx, args.Path, 100*1024, gitArgs...)
	text := stdout
	if text == "" && code == 0 {
		text = "(no diff)"
	}
	if stderr != "" {
		text += "\n" + stderr
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
	n := args.Limit
	if n <= 0 {
		n = 10
	}
	if n > 50 {
		n = 50
	}
	stdout, stderr, cwd, code := s.run(ctx, args.Path, 64*1024, "log", fmt.Sprintf("-%d", n), "--oneline", "--decorate")
	text := strings.TrimSpace(stdout)
	if stderr != "" {
		text += "\n" + stderr
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: code != 0,
	}, LogOut{Path: cwd, Log: stdout}, nil
}
