package native

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"

	"babylon/internal/policy"
)

// smbShare is what the guest probe learned about one share.
type smbShare struct {
	Name     string
	Readable bool
	Entries  int // number of entries seen in the share root (capped)
}

const smbMaxEntries = 50

// smbGuestProbe logs in over SMB with a user name that cannot exist and an empty
// password. A server that still grants a session maps unknown users to guest,
// so anyone can connect. It then lists share names and, for each non-hidden
// share, counts the entries in the root directory. It never reads file contents
// and never writes. Replaced in tests.
var smbGuestProbe = func(host string, port int) ([]smbShare, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 4*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "babylon-" + hex.EncodeToString(rnd[:]), Password: ""}}
	sess, err := d.Dial(conn)
	if err != nil {
		return nil, err
	}
	defer sess.Logoff()
	names, err := sess.ListSharenames()
	if err != nil {
		// A session was granted even though shares could not be listed.
		return []smbShare{}, nil
	}
	sort.Strings(names)
	var out []smbShare
	for _, n := range names {
		if strings.HasSuffix(n, "$") { // IPC$ and administrative shares
			continue
		}
		sh := smbShare{Name: n}
		if fs, err := sess.Mount(n); err == nil {
			if ents, err := fs.ReadDir("."); err == nil {
				sh.Readable, sh.Entries = true, min(len(ents), smbMaxEntries)
			}
			_ = fs.Umount()
		}
		out = append(out, sh)
	}
	return out, nil
}

var smbGuestAccess = Check{
	ID: "smb-guest-access", Name: "SMB server allows access without valid credentials", Family: "Windows",
	Safety: policy.SafetyProbe,
	Needs: func(e *Env) string {
		for _, s := range e.Services {
			if s.Proto == "tcp" && s.Port == 445 {
				return ""
			}
		}
		return "no SMB service on 445/tcp"
	},
	Run: func(e *Env) []Finding {
		var out []Finding
		for _, s := range e.Services {
			if s.Proto != "tcp" || s.Port != 445 {
				continue
			}
			shares, err := smbGuestProbe(e.Address, s.Port)
			if err != nil {
				continue // login refused (the normal case) or the service is not reachable
			}
			var readable, listed []string
			for _, sh := range shares {
				listed = append(listed, sh.Name)
				if sh.Readable {
					readable = append(readable, fmt.Sprintf("%s (%d entries)", sh.Name, sh.Entries))
				}
			}
			f := Finding{Port: s.Port, Proto: "tcp", Detection: "behaviour",
				Title: "SMB server grants a session to unknown users (guest access)", Severity: "medium",
				Synopsis:    "The SMB server accepts a login with a user name that does not exist and no password.",
				Description: "The server maps failed logins to a guest account. Anyone on the network can connect without credentials, enumerate shares and read those that allow guest access.",
				Remediation: "Disable guest access: on Samba set map to guest = Never and remove guest ok from shares; on Windows disable the Guest account and set RestrictAnonymous. Require authentication on every share.",
				Evidence:    "Login with a random user name and empty password succeeded.\nShares: " + strings.Join(listed, ", ")}
			if len(readable) > 0 {
				f.Severity = "high"
				f.Title = "SMB share readable without credentials (guest access)"
				f.Evidence += "\nReadable without credentials: " + strings.Join(readable, ", ")
			}
			out = append(out, f)
		}
		return out
	},
}

func smbChecks() []Check { return []Check{smbGuestAccess} }
