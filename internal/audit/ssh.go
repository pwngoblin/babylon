package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	CmdTimeout   = 10 * time.Second
	DialTimeout  = 10 * time.Second
	maxCmdOutput = 8 << 20
)

// Creds are held in memory only. Nothing here is ever written to the database;
// only Label is recorded with a scan.
type Creds struct {
	Label      string
	User       string
	Password   string
	KeyPath    string
	Passphrase string
	Port       int // default 22
}

// HostKeyPolicy decides how unknown host keys are treated.
type HostKeyPolicy struct {
	KnownHosts string // files consulted first (default ~/.ssh/known_hosts)
	// TrustNew allows unknown hosts and pins them to PinFile (trust on first
	// use). A host whose key CHANGED is always rejected.
	TrustNew bool
	PinFile  string // default ~/.babylon/known_hosts
}

// Runner executes one read-only command on a host.
type Runner interface {
	Run(ctx context.Context, cmd string) (string, error)
}

// ErrCommandNotAllowed is returned for any command outside the fixed
// collector set: the audit is read-only by construction.
var ErrCommandNotAllowed = errors.New("audit: command is not in the read-only allowlist")

// allowed is every command the collector may run. Keep it small and obvious;
// a test pins it against destructive verbs.
var allowed = map[string]bool{}

func allow(cmds ...string) {
	for _, c := range cmds {
		allowed[c] = true
	}
}

// Session is a live SSH connection.
type Session struct {
	client *ssh.Client
}

func (c Creds) authMethods() ([]ssh.AuthMethod, error) {
	var m []ssh.AuthMethod
	if c.KeyPath != "" {
		b, err := os.ReadFile(c.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("reading ssh key: %w", err)
		}
		var signer ssh.Signer
		if c.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(b, []byte(c.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(b)
		}
		if err != nil {
			return nil, fmt.Errorf("parsing ssh key (wrong passphrase or unsupported format?): %w", err)
		}
		m = append(m, ssh.PublicKeys(signer))
	}
	if c.Password != "" {
		pw := c.Password
		m = append(m, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			a := make([]string, len(qs))
			for i := range a {
				a[i] = pw
			}
			return a, nil
		}))
	}
	if len(m) == 0 {
		return nil, errors.New("no ssh credentials: give a key or a password")
	}
	return m, nil
}

var pinMu sync.Mutex // serializes TOFU appends across concurrent jobs

func (p HostKeyPolicy) callback() (ssh.HostKeyCallback, error) {
	home, _ := os.UserHomeDir()
	files := []string{}
	if p.KnownHosts != "" {
		files = append(files, p.KnownHosts)
	} else if home != "" {
		files = append(files, filepath.Join(home, ".ssh", "known_hosts"))
	}
	pin := p.PinFile
	if pin == "" && home != "" {
		pin = filepath.Join(home, ".babylon", "known_hosts")
	}
	var existing []string
	for _, f := range append(files, pin) {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); err == nil {
			existing = append(existing, f)
		}
	}
	var base ssh.HostKeyCallback
	if len(existing) > 0 {
		cb, err := knownhosts.New(existing...)
		if err != nil {
			return nil, fmt.Errorf("reading known_hosts: %w", err)
		}
		base = cb
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if base != nil {
			err := base(hostname, remote, key)
			if err == nil {
				return nil
			}
			var ke *knownhosts.KeyError
			if !errors.As(err, &ke) || len(ke.Want) > 0 {
				// A key mismatch (possible MITM) or other error: never auto-accept.
				return fmt.Errorf("host key verification failed for %s: %w (if the key legitimately changed, update known_hosts)", hostname, err)
			}
		}
		if !p.TrustNew {
			return fmt.Errorf("host key for %s is not in known_hosts (%s); connect once with ssh to verify it, or pass --trust-new-hosts to pin it on first use", hostname, ssh.FingerprintSHA256(key))
		}
		if pin == "" {
			return errors.New("cannot pin host key: no home directory")
		}
		pinMu.Lock()
		defer pinMu.Unlock()
		if err := os.MkdirAll(filepath.Dir(pin), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(pin, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = fmt.Fprintln(f, knownhosts.Line([]string{knownhosts.Normalize(remote.String())}, key))
		return err
	}, nil
}

// Dial connects and authenticates. The context bounds the whole handshake.
func Dial(ctx context.Context, host string, c Creds, pol HostKeyPolicy) (*Session, error) {
	methods, err := c.authMethods()
	if err != nil {
		return nil, err
	}
	hk, err := pol.callback()
	if err != nil {
		return nil, err
	}
	port := c.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	cfg := &ssh.ClientConfig{User: c.User, Auth: methods, HostKeyCallback: hk, Timeout: DialTimeout, ClientVersion: "SSH-2.0-Babylon"}
	d := net.Dialer{Timeout: DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh connect %s: %w", addr, err)
	}
	// Bound the handshake by the context deadline.
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	conn.SetDeadline(time.Time{})
	return &Session{client: ssh.NewClient(cc, chans, reqs)}, nil
}

// Run executes an allowlisted command with a 10s timeout. A non-zero exit is
// returned with the output collected so far, since many probes (`sshd -T` as a
// non-root user) fail harmlessly.
func (s *Session) Run(ctx context.Context, cmd string) (string, error) {
	if !allowed[cmd] {
		return "", ErrCommandNotAllowed
	}
	sess, err := s.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var out, errb limitBuf
	out.max, errb.max = maxCmdOutput, 1<<16
	sess.Stdout, sess.Stderr = &out, &errb
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	timer := time.NewTimer(CmdTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return out.String(), err
	case <-timer.C:
		sess.Close()
		return out.String(), fmt.Errorf("command timed out after %s", CmdTimeout)
	case <-ctx.Done():
		sess.Close()
		return out.String(), ctx.Err()
	}
}

func (s *Session) Close() error { return s.client.Close() }

type limitBuf struct {
	bytes.Buffer
	max int
}

func (b *limitBuf) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil // swallow the rest: never block the remote
}
