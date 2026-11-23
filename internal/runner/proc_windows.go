//go:build windows

package runner

import (
	"os/exec"
	"strconv"
	"time"
)

func setProcessGroup(cmd *exec.Cmd) {}

// killGroup ends the process and its children. Windows has no SIGTERM for
// console tools, so `taskkill /T` (tree) is used, forced after the grace period.
func killGroup(cmd *exec.Cmd, grace time.Duration, done <-chan struct{}) {
	if cmd.Process == nil {
		return
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	if grace > 0 {
		_ = exec.Command("taskkill", "/T", "/PID", pid).Run()
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
	_ = exec.Command("taskkill", "/T", "/F", "/PID", pid).Run()
}
