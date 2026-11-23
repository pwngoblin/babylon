package pack

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"babylon/internal/native"
	"babylon/internal/store"
)

// RunFixtures serves each test's canned responses from a local mock and checks
// the verdict. This is what makes "every check has a mock-target test" free.
// The mock listens on a random port, so the check's port/service scope is
// replaced by that port for the test; scope matching is unit-tested separately.
func RunFixtures(d Def) error {
	for _, t := range d.Tests {
		env, port, stop, err := d.fixtureEnv(t)
		if err != nil {
			return fmt.Errorf("test %q: %w", t.Name, err)
		}
		dd := d
		dd.When = When{Ports: []int{port}, Proto: d.proto()}
		chk := Compile(dd)
		skip := chk.Needs(env)
		var found []native.Finding
		if skip == "" {
			found = chk.Run(env)
		}
		stop()
		switch {
		case t.Want == "finding" && len(found) == 0:
			return fmt.Errorf("test %q: expected a finding, got none (skip reason %q)", t.Name, skip)
		case t.Want == "none" && len(found) > 0:
			return fmt.Errorf("test %q: expected no finding, got %q", t.Name, found[0].Title)
		}
		for _, f := range found {
			if strings.Contains(f.Title+f.Synopsis+f.Description+f.Remediation+f.Evidence, "${") {
				return fmt.Errorf("test %q: unexpanded ${...} placeholder in the finding", t.Name)
			}
		}
	}
	return nil
}

func (d *Def) fixtureEnv(t Test) (*native.Env, int, func(), error) {
	env := &native.Env{Address: "127.0.0.1", AssetID: 1, KB: map[string]json.RawMessage{}}
	if d.Kind == "passive" {
		fs := t.Service
		port := fs.Port
		if port == 0 {
			port = firstPort(d)
		}
		svc := store.ServiceInfo{Address: env.Address, Port: port, Proto: d.proto(), Name: fs.Name, Product: fs.Product,
			Version: fs.Version, Banner: fs.Banner, Extra: fs.Extra, OS: fs.OS}
		if fs.CPE != "" {
			svc.CPEs = []string{fs.CPE}
		}
		env.Services = []store.ServiceInfo{svc}
		for id, out := range t.Scripts {
			env.KB[store.ScriptKey(port, d.proto(), id)] = mustJSON(out)
		}
		return env, port, func() {}, nil
	}
	port, stop, err := d.mock(t)
	if err != nil {
		return nil, 0, nil, err
	}
	env.Services = []store.ServiceInfo{{Address: env.Address, Port: port, Proto: d.proto(), Name: "fixture"}}
	return env, port, stop, nil
}

func firstPort(d *Def) int {
	if len(d.When.Ports) > 0 {
		return d.When.Ports[0]
	}
	return 1
}

// mock starts a server speaking the check's transport and returns its port.
func (d *Def) mock(t Test) (int, func(), error) {
	switch d.Transport {
	case "http":
		return mockHTTP(d, t)
	case "udp":
		return mockUDP(d, t)
	}
	return mockTCP(d, t)
}

func mockHTTP(d *Def, t Test) (int, func(), error) {
	n := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := n
		n++
		if i >= len(t.Responses) {
			http.Error(w, "unexpected request", 500)
			return
		}
		resp := t.Responses[i]
		for k, v := range resp.Header {
			w.Header().Set(k, v)
		}
		if resp.Status == 0 {
			resp.Status = 200
		}
		w.WriteHeader(resp.Status)
		_, _ = w.Write([]byte(resp.Body))
	})
	var srv *httptest.Server
	if d.Steps[0].HTTP.Scheme == "https" {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	return port, srv.Close, nil
}

func mockTCP(d *Def, t Test) (int, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 8192)
		for i, st := range d.Steps {
			if st.Send != "" || st.SendHex != "" {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
			if i < len(t.Responses) {
				_, _ = c.Write([]byte(t.Responses[i].Data))
			}
		}
		time.Sleep(300 * time.Millisecond) // let the client read before the close
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }, nil
}

func mockUDP(d *Def, t Test) (int, func(), error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}
	go func() {
		buf := make([]byte, 8192)
		_, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if len(t.Responses) > 0 && t.Responses[0].Data != "" {
			_, _ = pc.WriteTo([]byte(t.Responses[0].Data), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port, func() { pc.Close() }, nil
}

func mustJSON(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
