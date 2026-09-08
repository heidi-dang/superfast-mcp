package shell

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Service struct {
	roots   []string
	timeout time.Duration
}

func New(roots []string) *Service {
	return &Service{roots: roots, timeout: 60 * time.Second}
}

type RunArgs struct {
	Command string `json:"command" jsonschema:"shell command to run"`
	Cwd     string `json:"cwd,omitempty" jsonschema:"working directory (must be under a root)"`
	Timeout int    `json:"timeout_sec,omitempty" jsonschema:"timeout in seconds (default 60, max 300)"`
}

type RunOut struct {
	Command  string `json:"command"`
	Cwd      string `json:"cwd"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	TimedOut bool   `json:"timed_out"`
}

func (s *Service) Run(ctx context.Context, req *mcp.CallToolRequest, args RunArgs) (*mcp.CallToolResult, RunOut, error) {
	cwd := args.Cwd
	if cwd == "" && len(s.roots) > 0 {
		cwd = s.roots[0]
	}
	to := s.timeout
	if args.Timeout > 0 {
		to = time.Duration(args.Timeout) * time.Second
		if to > 5*time.Minute {
			to = 5 * time.Minute
		}
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-lc", args.Command)
	cmd.Dir = cwd
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	out := RunOut{
		Command: args.Command,
		Cwd:     cwd,
		Stdout:  truncate(stdout.String(), 64*1024),
		Stderr:  truncate(stderr.String(), 32*1024),
	}
	if ctx.Err() == context.DeadlineExceeded {
		out.TimedOut = true
		out.ExitCode = -1
	} else if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			out.ExitCode = ee.ExitCode()
		} else {
			out.ExitCode = -1
		}
	}

	text := fmt.Sprintf("$ %s\nexit=%d", args.Command, out.ExitCode)
	if out.TimedOut {
		text += " (timed out)"
	}
	if out.Stdout != "" {
		text += "\n" + out.Stdout
	}
	if out.Stderr != "" {
		text += "\n[stderr]\n" + out.Stderr
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: out.ExitCode != 0 && !out.TimedOut,
	}, out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n...[truncated]"
}
