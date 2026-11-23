//go:build !windows

package runner

import (
	"os/exec"
	"syscall"
	"time"
)

func setProcessGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// killGroup sends SIGTERM to the process group, waits grace, then SIGKILL.
// If done is non-nil, a closed done channel short-circuits the wait.
func killGroup(cmd *exec.Cmd, grace time.Duration, done <-chan struct{}) {
	if cmd.Process == nil {
		return
	}
	pgid := -cmd.Process.Pid
	if grace > 0 {
		_ = syscall.Kill(pgid, syscall.SIGTERM)
		t := time.NewTimer(grace)
		defer t.Stop()
		if done == nil {
			<-t.C
		} else {
			select {
			case <-t.C:
			case <-done:
				return
			}
		}
	}
	_ = syscall.Kill(pgid, syscall.SIGKILL)
}
