package pack

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"babylon/internal/native"
	"babylon/internal/policy"
	"babylon/internal/store"
)

const (
	dialTimeout  = 4 * time.Second
	checkTimeout = 10 * time.Second // wall-clock cap per probed service
	idleRead     = 200 * time.Millisecond
)

// Compile turns a validated Def into a native check.
func Compile(d Def) native.Check {
	safety := policy.SafetyReadOnly
	if d.Kind == "probe" {
		safety = policy.SafetyProbe
	}
	c := native.Check{
		ID: d.ID, Name: d.Name, Family: d.Family, Safety: safety, Controls: d.Controls,
		Needs: func(e *native.Env) string {
			if len(d.services(e)) == 0 {
				return "no open service matches " + d.scope()
			}
			return ""
		},
	}
	c.Run = func(e *native.Env) []native.Finding {
		var out []native.Finding
		for _, s := range d.services(e) {
			if ev, caps, ok := d.evaluate(e, s); ok {
				out = append(out, d.finding(s, ev, caps))
			}
		}
		return out
	}
	return c
}

func (d *Def) scope() string {
	var parts []string
	if len(d.When.Ports) > 0 {
		p := make([]string, len(d.When.Ports))
		for i, n := range d.When.Ports {
			p[i] = strconv.Itoa(n)
		}
		parts = append(parts, "port "+strings.Join(p, ","))
	}
	if len(d.When.Services) > 0 {
		parts = append(parts, "service "+strings.Join(d.When.Services, ","))
	}
	return strings.Join(parts, " or ")
}

func (d *Def) proto() string {
	switch {
	case d.When.Proto != "":
		return d.When.Proto
	case d.Transport == "udp":
		return "udp"
	}
	return "tcp"
}

// services returns the open services the check applies to.
func (d *Def) services(e *native.Env) []store.ServiceInfo {
	var out []store.ServiceInfo
	for _, s := range e.Services {
		if s.Proto != d.proto() {
			continue
		}
		if d.matchesScope(s) {
			out = append(out, s)
		}
	}
	return out
}

func (d *Def) matchesScope(s store.ServiceInfo) bool {
	for _, p := range d.When.Ports {
		if s.Port == p {
			return true
		}
	}
	for _, n := range d.When.Services {
		if strings.EqualFold(s.Name, n) {
			return true
		}
	}
	return false
}

func (d *Def) evaluate(e *native.Env, s store.ServiceInfo) (string, map[string]string, bool) {
	if d.Kind == "passive" {
		return d.evalPassive(e, s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	switch d.Transport {
	case "http":
		return d.runHTTP(ctx, e.Address, s)
	case "udp":
		return d.runUDP(ctx, e.Address, s)
	}
	return d.runTCP(ctx, e.Address, s)
}

func (d *Def) finding(s store.ServiceInfo, evidence string, caps map[string]string) native.Finding {
	// ${product}, ${version}, ${name} and ${port} are always available; named
	// regex groups from the check override them.
	vars := map[string]string{"product": s.Product, "version": s.Version, "name": s.Name, "port": strconv.Itoa(s.Port)}
	for k, v := range caps {
		vars[k] = v
	}
	sub := func(t string) string { return expand(t, vars) }
	conf, det := d.Confidence, "behaviour"
	if d.Kind == "passive" {
		det = "version"
		if conf == "" {
			conf = "firm"
		}
	}
	return native.Finding{
		Port: s.Port, Proto: s.Proto, Title: sub(d.Finding.Title), Severity: d.Severity,
		CVSS: d.Finding.CVSS, CVEs: d.Finding.CVEs,
		Synopsis: sub(d.Finding.Synopsis), Description: sub(d.Finding.Description),
		Remediation: sub(d.Finding.Remediation), Evidence: sub(evidence),
		Confidence: conf, Detection: det,
	}
}

// expand replaces ${name} with a captured group.
func expand(t string, caps map[string]string) string {
	if len(caps) == 0 || !strings.Contains(t, "${") {
		return t
	}
	for k, v := range caps {
		t = strings.ReplaceAll(t, "${"+k+"}", v)
	}
	return t
}

// ---- passive ----

func (d *Def) evalPassive(e *native.Env, s store.ServiceInfo) (string, map[string]string, bool) {
	caps := map[string]string{}
	var evidence []string
	for _, c := range d.Match {
		val := passiveValue(e, s, c.Field)
		m := c.re.FindStringSubmatch(val)
		if (m != nil) == c.Not {
			return "", nil, false
		}
		if m != nil {
			evidence = append(evidence, fmt.Sprintf("%s: %s", c.Field, snippet(m[0], 200)))
			addCaptures(caps, c.re, m)
		}
	}
	return strings.Join(evidence, "\n"), caps, true
}

func passiveValue(e *native.Env, s store.ServiceInfo, field string) string {
	switch {
	case field == "banner":
		return s.Banner
	case field == "product":
		return s.Product
	case field == "version":
		return s.Version
	case field == "name":
		return s.Name
	case field == "extra":
		return s.Extra
	case field == "os":
		return s.OS
	case field == "cpe":
		return strings.Join(s.CPEs, " ")
	case strings.HasPrefix(field, "script:"):
		out, _ := e.Script(s.Port, s.Proto, strings.TrimPrefix(field, "script:"))
		return out
	}
	return ""
}

func addCaptures(caps map[string]string, re *regexp.Regexp, m []string) {
	for i, n := range re.SubexpNames() {
		if n != "" && i < len(m) {
			caps[n] = snippet(m[i], 100)
		}
	}
}

// ---- probe: shared ----

// check applies one step's expectation to a reply and returns whether it holds.
func (x *Expect) check(status int, hdr http.Header, body string, caps map[string]string) bool {
	if x.Status != 0 && status != x.Status {
		return false
	}
	for name, re := range x.header {
		if !re.MatchString(hdr.Get(name)) {
			return false
		}
	}
	if x.not != nil && x.not.MatchString(body) {
		return false
	}
	if x.body != nil {
		m := x.body.FindStringSubmatch(body)
		if m == nil {
			return false
		}
		addCaptures(caps, x.body, m)
	}
	return true
}

func (s *Step) payload() ([]byte, error) {
	if s.SendHex != "" {
		b, err := hex.DecodeString(strings.ReplaceAll(s.SendHex, " ", ""))
		if err != nil {
			return nil, fmt.Errorf("send_hex: %w", err)
		}
		return b, nil
	}
	return []byte(s.Send), nil
}

func snippet(s string, n int) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// ---- probe: tcp ----

// readSome reads up to max bytes: it waits for the first data, then keeps
// reading until the peer goes idle, closes, or the cap is reached.
func readSome(c net.Conn, max int) string {
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for len(buf) < max {
		n, err := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			_ = c.SetReadDeadline(time.Now().Add(idleRead))
		}
		if err != nil {
			break
		}
	}
	if len(buf) > max {
		buf = buf[:max]
	}
	return string(buf)
}

func (d *Def) runTCP(ctx context.Context, host string, s store.ServiceInfo) (string, map[string]string, bool) {
	dl := net.Dialer{Timeout: dialTimeout}
	c, err := dl.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(s.Port)))
	if err != nil {
		return "", nil, false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(checkTimeout))
	caps := map[string]string{}
	var evidence []string
	for _, st := range d.Steps {
		if payload, _ := st.payload(); len(payload) > 0 {
			if _, err := c.Write(payload); err != nil {
				return "", nil, false
			}
			evidence = append(evidence, fmt.Sprintf("sent %d bytes", len(payload)))
		}
		reply := readSome(c, st.Read)
		if !st.Expect.check(0, nil, reply, caps) {
			return "", nil, false
		}
		evidence = append(evidence, "received: "+snippet(reply, 300))
	}
	return strings.Join(evidence, "\n"), caps, true
}

// ---- probe: udp ----

func (d *Def) runUDP(ctx context.Context, host string, s store.ServiceInfo) (string, map[string]string, bool) {
	st := d.Steps[0]
	payload, _ := st.payload()
	dst, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(s.Port)))
	if err != nil {
		return "", nil, false
	}
	network := "udp4"
	if dst.IP.To4() == nil {
		network = "udp6"
	}
	// Unconnected socket: replies from another port of the probed IP still count.
	c, err := net.ListenUDP(network, nil)
	if err != nil {
		return "", nil, false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.WriteToUDP(payload, dst); err != nil {
		return "", nil, false
	}
	buf := make([]byte, st.Read)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return "", nil, false
		}
		if !from.IP.Equal(dst.IP) {
			continue
		}
		caps := map[string]string{}
		reply := string(buf[:n])
		if !st.Expect.check(0, nil, reply, caps) {
			return "", nil, false
		}
		return fmt.Sprintf("sent %d bytes\nreceived: %s", len(payload), snippet(reply, 300)), caps, true
	}
}

// ---- probe: http ----

var httpClient = &http.Client{
	Timeout: 6 * time.Second,
	Transport: &http.Transport{
		// Probes identify exposed services and send no credentials, so certificate
		// trust is irrelevant (and device certificates are usually self-signed).
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: dialTimeout}).DialContext,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func schemeFor(h *HTTPStep, s store.ServiceInfo) string {
	if h.Scheme != "auto" {
		return h.Scheme
	}
	if s.Tunnel == "ssl" || strings.Contains(strings.ToLower(s.Name), "https") {
		return "https"
	}
	return "http"
}

func (d *Def) runHTTP(ctx context.Context, host string, s store.ServiceInfo) (string, map[string]string, bool) {
	caps := map[string]string{}
	var evidence []string
	for _, st := range d.Steps {
		u := schemeFor(st.HTTP, s) + "://" + net.JoinHostPort(host, strconv.Itoa(s.Port)) + st.HTTP.Path
		req, err := http.NewRequestWithContext(ctx, st.HTTP.Method, u, nil)
		if err != nil {
			return "", nil, false
		}
		req.Header.Set("User-Agent", "babylon-scanner")
		resp, err := httpClient.Do(req)
		if err != nil {
			return "", nil, false
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, int64(st.Read)))
		resp.Body.Close()
		body := string(b)
		if !st.Expect.check(resp.StatusCode, resp.Header, body, caps) {
			return "", nil, false
		}
		line := fmt.Sprintf("%s %s -> %d", st.HTTP.Method, st.HTTP.Path, resp.StatusCode)
		for name := range st.Expect.header {
			line += fmt.Sprintf("\n%s: %s", name, snippet(resp.Header.Get(name), 200))
		}
		evidence = append(evidence, line+"\n"+snippet(body, 300))
	}
	return strings.Join(evidence, "\n"), caps, true
}
