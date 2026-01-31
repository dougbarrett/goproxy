package runner

import (
	"os"
	"os/exec"
	"strings"
)

// Runner manages a subprocess with proxy environment variables injected.
type Runner struct {
	cmd *exec.Cmd
}

// New creates a Runner that will execute the given command with HTTP_PROXY
// and HTTPS_PROXY environment variables set to proxyURL.
func New(proxyURL string, args []string) *Runner {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = buildEnv(os.Environ(), proxyURL)
	return &Runner{cmd: cmd}
}

// Start begins executing the subprocess.
func (r *Runner) Start() error {
	return r.cmd.Start()
}

// Wait waits for the subprocess to exit and returns its exit code.
func (r *Runner) Wait() int {
	if err := r.cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

// Signal sends a signal to the subprocess.
func (r *Runner) Signal(sig os.Signal) error {
	if r.cmd.Process == nil {
		return nil
	}
	return r.cmd.Process.Signal(sig)
}

// buildEnv filters out existing proxy vars and injects new ones.
func buildEnv(env []string, proxyURL string) []string {
	filtered := make([]string, 0, len(env)+4)
	for _, e := range env {
		key := strings.ToUpper(strings.SplitN(e, "=", 2)[0])
		if key == "HTTP_PROXY" || key == "HTTPS_PROXY" {
			continue
		}
		filtered = append(filtered, e)
	}
	return append(filtered,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
	)
}
