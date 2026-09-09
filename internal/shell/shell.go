package shell

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/heidi-dang/superfast-mcp/internal/limitio"
	"github.com/heidi-dang/superfast-mcp/internal/roots"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Service struct {
	roots   *roots.Set
	timeout time.Duration
}

func New(rootSet *roots.Set) *Service {
	return &Service{roots: rootSet, timeout: 60 * time.Second}
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
	if strings.TrimSpace(args.Command) == "" {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "command must not be empty"}}}, RunOut{}, nil
	}

	cwd, err := s.roots.ResolveExistingDir(args.Cwd)
	if err != nil {
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, RunOut{}, nil
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	stdout := limitio.NewBuffer(64 * 1024)
	stderr := limitio.NewBuffer(32 * 1024)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err = cmd.Run()
	out := RunOut{
		Command: args.Command,
		Cwd:     cwd,
		Stdout:  stdout.String(),
		Stderr:  stderr.String(),
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
		IsError: out.ExitCode != 0,
	}, out, nil
}
