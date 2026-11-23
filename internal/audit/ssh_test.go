package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testServer is an in-process SSH server answering exec requests from a map.
type testServer struct {
	addr   string
	port   int
	execed chan string
}

func newTestServer(t *testing.T, hostKey ssh.Signer, password string, answers map[string]string) *testServer {
	t.Helper()
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "audit" && string(pw) == password {
			return nil, nil
		}
		return nil, os.ErrPermission
	}}
	cfg.AddHostKey(hostKey)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	s := &testServer{addr: "127.0.0.1", port: l.Addr().(*net.TCPAddr).Port, execed: make(chan string, 64)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						return
					}
					go func() {
						for r := range creqs {
							if r.Type != "exec" {
								r.Reply(false, nil)
								continue
							}
							cmd := string(r.Payload[4:])
							s.execed <- cmd
							r.Reply(true, nil)
							ch.Write([]byte(answers[cmd]))
							ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							ch.Close()
						}
					}()
				}
			}()
		}
	}()
	return s
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSSHHostKeyPolicyAndRun(t *testing.T) {
	dir := t.TempDir()
	key := newSigner(t)
	srv := newTestServer(t, key, "pw", map[string]string{cmdUname: "Linux 6.1 x86_64\n"})
	creds := Creds{User: "audit", Password: "pw", Port: srv.port}
	known := filepath.Join(dir, "known_hosts")
	pin := filepath.Join(dir, "pinned")
	os.WriteFile(known, nil, 0o600)
	ctx := context.Background()

	// 1. Unknown host, strict: refused, with a useful message.
	_, err := Dial(ctx, srv.addr, creds, HostKeyPolicy{KnownHosts: known, PinFile: pin})
	if err == nil || !strings.Contains(err.Error(), "not in known_hosts") || !strings.Contains(err.Error(), "--trust-new-hosts") {
		t.Fatalf("strict policy must refuse unknown hosts, got %v", err)
	}
	if _, statErr := os.Stat(pin); statErr == nil {
		t.Fatal("a refused host must not be pinned")
	}

	// 2. Trust on first use pins the key; the next strict connection works.
	s, err := Dial(ctx, srv.addr, creds, HostKeyPolicy{KnownHosts: known, PinFile: pin, TrustNew: true})
	if err != nil {
		t.Fatalf("TOFU dial: %v", err)
	}
	out, err := s.Run(ctx, cmdUname)
	if err != nil || strings.TrimSpace(out) != "Linux 6.1 x86_64" {
		t.Fatalf("run: %q %v", out, err)
	}
	// 3. Commands outside the allowlist never reach the server.
	for _, bad := range []string{"rm -rf /", "cat /etc/shadow", cmdUname + "; id"} {
		if _, err := s.Run(ctx, bad); err != ErrCommandNotAllowed {
			t.Errorf("%q: want ErrCommandNotAllowed, got %v", bad, err)
		}
	}
	s.Close()
	for len(srv.execed) > 1 {
		<-srv.execed
	}
	if got := <-srv.execed; got != cmdUname {
		t.Errorf("server received %q", got)
	}
	if len(srv.execed) != 0 {
		t.Errorf("unexpected extra commands reached the server")
	}
	if fi, err := os.Stat(pin); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("pin file: %v %v", fi, err)
	}
	s, err = Dial(ctx, srv.addr, creds, HostKeyPolicy{KnownHosts: pin, PinFile: pin})
	if err != nil {
		t.Fatalf("pinned host must connect under the strict policy: %v", err)
	}
	s.Close()

	// 4. A changed host key is rejected even with --trust-new-hosts.
	srv2 := newTestServer(t, newSigner(t), "pw", nil)
	// reuse the pinned entry by serving the new key on the same port is not possible, so
	// rewrite the pin file's host to the new port with the old key.
	b, _ := os.ReadFile(pin)
	forged := strings.ReplaceAll(string(b), "]:"+strconv.Itoa(srv.port), "]:"+strconv.Itoa(srv2.port))
	os.WriteFile(pin, []byte(forged), 0o600)
	_, err = Dial(ctx, srv2.addr, Creds{User: "audit", Password: "pw", Port: srv2.port}, HostKeyPolicy{KnownHosts: pin, PinFile: pin, TrustNew: true})
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("a changed host key must be rejected, got %v", err)
	}

	// 5. Wrong password.
	if _, err := Dial(ctx, srv.addr, Creds{User: "audit", Password: "nope", Port: srv.port}, HostKeyPolicy{KnownHosts: pin, PinFile: pin}); err == nil {
		t.Error("wrong password must fail")
	}
	// 6. No credentials at all.
	if _, err := Dial(ctx, srv.addr, Creds{User: "audit", Port: srv.port}, HostKeyPolicy{}); err == nil || !strings.Contains(err.Error(), "no ssh credentials") {
		t.Errorf("missing credentials: %v", err)
	}
}
