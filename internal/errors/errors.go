// Package errors defines Babylon's typed error values.
package errors

import (
	"errors"
	"fmt"
)

var (
	ErrToolMissing = errors.New("required tool not found in PATH")
	ErrTimeout     = errors.New("command timed out")
	ErrOutputLimit = errors.New("command output exceeded limit")
)

// ToolFailed reports a non-zero exit from an external tool.
type ToolFailed struct {
	Tool       string
	ExitCode   int
	StderrTail string
}

func (e *ToolFailed) Error() string {
	return fmt.Sprintf("%s exited with code %d: %s", e.Tool, e.ExitCode, e.StderrTail)
}
