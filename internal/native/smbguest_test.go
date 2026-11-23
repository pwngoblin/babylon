package native

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"babylon/internal/store"
)

func smbEnv() *Env {
	return &Env{Address: "10.0.0.5", Services: []store.ServiceInfo{{Port: 445, Proto: "tcp", Name: "microsoft-ds"}}}
}

func withProbe(t *testing.T, fn func(string, int) ([]smbShare, error)) {
	old := smbGuestProbe
	smbGuestProbe = fn
	t.Cleanup(func() { smbGuestProbe = old })
}

func TestSMBGuestAccessFindings(t *testing.T) {
	withProbe(t, func(string, int) ([]smbShare, error) {
		return []smbShare{{Name: "pub", Readable: true, Entries: 3}, {Name: "private"}}, nil
	})
	got := smbGuestAccess.Run(smbEnv())
	if len(got) != 1 || got[0].Severity != "high" || !strings.Contains(got[0].Evidence, "pub (3 entries)") || strings.Contains(got[0].Evidence, "private (") {
		t.Fatalf("readable share: %+v", got)
	}
	withProbe(t, func(string, int) ([]smbShare, error) { return []smbShare{{Name: "private"}}, nil })
	if got := smbGuestAccess.Run(smbEnv()); len(got) != 1 || got[0].Severity != "medium" {
		t.Fatalf("session without a readable share is medium: %+v", got)
	}
	withProbe(t, func(string, int) ([]smbShare, error) { return nil, errors.New("STATUS_LOGON_FAILURE") })
	if got := smbGuestAccess.Run(smbEnv()); len(got) != 0 {
		t.Fatalf("a refused login is the normal case and must not report: %+v", got)
	}
}

func TestSMBGuestAccessNeedsAnSMBServiceAndIsProbeLevel(t *testing.T) {
	if smbGuestAccess.Needs(&Env{Services: []store.ServiceInfo{{Port: 80, Proto: "tcp"}}}) == "" {
		t.Fatal("applied to a host without SMB")
	}
	if smbGuestAccess.Needs(smbEnv()) != "" {
		t.Fatal("did not apply to 445/tcp")
	}
	for _, c := range Available(0) { // read-only scans must not load it
		if c.ID == "smb-guest-access" {
			t.Fatal("an active probe is offered without --allow-active")
		}
	}
}

// Live check against the lab Samba container (babylon lab up): guest share "pub".
func TestSMBGuestLiveSamba(t *testing.T) {
	if testing.Short() {
		t.Skip("live lab test")
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:445", time.Second)
	if err != nil {
		t.Skip("lab Samba not running")
	}
	c.Close()
	shares, err := smbGuestProbe("127.0.0.1", 445)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range shares {
		if s.Name == "pub" {
			found = true
		}
		if strings.HasSuffix(s.Name, "$") {
			t.Errorf("hidden share listed: %s", s.Name)
		}
	}
	if !found {
		t.Fatalf("lab share pub not found: %+v", shares)
	}
}
