package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

// WinCreds are the Windows credentials for one scan. They live only in memory:
// they come from the environment and are never written to the database.
type WinCreds struct {
	User       string
	Password   string
	Label      string
	Port       int  // default 5986 (HTTPS) or 5985 with HTTP
	HTTP       bool // use plain HTTP transport (NTLM message encryption still protects the payload)
	SkipVerify bool // accept self-signed HTTPS certificates (common on Windows)
}

func (c WinCreds) port() int {
	if c.Port != 0 {
		return c.Port
	}
	if c.HTTP {
		return 5985
	}
	return 5986
}

// Validate checks the settings before any connection is made.
func (c WinCreds) Validate() error {
	if c.User == "" {
		return errors.New("WinRM user is required")
	}
	if c.Password == "" {
		return errors.New("WinRM password is empty (set it in the environment variable named by --winrm-password-env)")
	}
	return nil
}

// WinSession runs the fixed PowerShell scripts over WinRM.
type WinSession struct {
	client *winrm.Client
}

// DialWinRM prepares a WinRM client. It authenticates with NTLM and, because
// NTLM message encryption is enabled, the payload is encrypted even over HTTP.
// Connections are made lazily, on the first script.
func DialWinRM(ctx context.Context, host string, c WinCreds) (*WinSession, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	ep := winrm.NewEndpoint(host, c.port(), !c.HTTP, c.SkipVerify, nil, nil, nil, 30*time.Second)
	params := winrm.DefaultParameters
	enc, err := winrm.NewEncryption("ntlm")
	if err != nil {
		return nil, err
	}
	params.TransportDecorator = func() winrm.Transporter { return enc }
	cl, err := winrm.NewClientWithParameters(ep, c.User, c.Password, params)
	if err != nil {
		return nil, err
	}
	return &WinSession{client: cl}, nil
}

// Run executes an allowlisted PowerShell script and returns its output.
func (s *WinSession) Run(ctx context.Context, script string) (string, error) {
	if !winAllowed[script] {
		return "", ErrCommandNotAllowed
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stdout, stderr, code, err := s.client.RunPSWithContextWithString(cctx, script, "")
	if err != nil {
		return "", err
	}
	if code != 0 && strings.TrimSpace(stdout) == "" {
		return "", fmt.Errorf("script exited with code %d: %s", code, strings.TrimSpace(firstLine(stderr)))
	}
	return stdout, nil
}

func (s *WinSession) Close() {}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
