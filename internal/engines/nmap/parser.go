// Package nmap wraps the Nmap binary: building allowlisted argv, running it,
// and streaming its XML output into Babylon's domain model.
package nmap

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"babylon/internal/model"
)

// ErrTruncated means the XML ended before Nmap's closing <runstats>, i.e. the
// scan was killed or crashed. Hosts parsed before the cut are still delivered.
var ErrTruncated = errors.New("nmap xml truncated (scan did not finish)")

// Stats summarizes a parse.
type Stats struct {
	Hosts    int
	Finished bool
}

// maxElem guards against pathological nesting/size in a single <host>.
const maxPortsPerHost = 70000

type xHost struct {
	Status struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr   string `xml:"addr,attr"`
		Type   string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []xPort `xml:"ports>port"`
	OS    struct {
		Matches []struct {
			Name     string `xml:"name,attr"`
			Accuracy string `xml:"accuracy,attr"`
			Classes  []struct {
				Family string   `xml:"osfamily,attr"`
				CPEs   []string `xml:"cpe"`
			} `xml:"osclass"`
		} `xml:"osmatch"`
	} `xml:"os"`
}

type xPort struct {
	Proto string `xml:"protocol,attr"`
	ID    string `xml:"portid,attr"`
	State struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string   `xml:"name,attr"`
		Product string   `xml:"product,attr"`
		Version string   `xml:"version,attr"`
		Extra   string   `xml:"extrainfo,attr"`
		Tunnel  string   `xml:"tunnel,attr"`
		CPEs    []string `xml:"cpe"`
	} `xml:"service"`
	Scripts []xScript `xml:"script"`
}

type xScript struct {
	ID     string   `xml:"id,attr"`
	Output string   `xml:"output,attr"`
	Elems  []xElem  `xml:"elem"`
	Tables []xTable `xml:"table"`
}

type xElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type xTable struct {
	Key    string   `xml:"key,attr"`
	Elems  []xElem  `xml:"elem"`
	Tables []xTable `xml:"table"`
}

// Parse streams Nmap XML from r, calling fn once per <host>. Memory use is
// bounded by the largest single host, not the document. If fn returns an error
// parsing stops and that error is returned.
func Parse(r io.Reader, fn func(model.Host) error) (Stats, error) {
	dec := xml.NewDecoder(newSanitizer(r))
	dec.Strict = true
	dec.Entity = nil // never resolve custom entities (no XXE surface)

	var st Stats
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if !st.Finished {
				return st, ErrTruncated
			}
			return st, nil
		}
		if err != nil {
			if st.Hosts > 0 || !st.Finished {
				return st, fmt.Errorf("%w: %v", ErrTruncated, err)
			}
			return st, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "host":
			var xh xHost
			if err := dec.DecodeElement(&xh, &se); err != nil {
				return st, fmt.Errorf("decode host: %w", err)
			}
			h, err := convertHost(xh)
			if err != nil {
				return st, err
			}
			st.Hosts++
			if err := fn(h); err != nil {
				return st, err
			}
		case "runstats":
			st.Finished = true
		}
	}
}

func convertHost(x xHost) (model.Host, error) {
	h := model.Host{State: x.Status.State, Reason: x.Status.Reason}
	for _, a := range x.Addresses {
		switch a.Type {
		case "ipv4", "ipv6":
			if h.Address == "" {
				h.Address = a.Addr
			}
		case "mac":
			h.MAC, h.Vendor = strings.ToLower(a.Addr), a.Vendor
		}
	}
	if h.Address == "" {
		return h, errors.New("host without ip address")
	}
	seen := map[string]bool{}
	for _, hn := range x.Hostnames {
		if hn.Name != "" && !seen[hn.Name] {
			seen[hn.Name] = true
			h.Hostnames = append(h.Hostnames, hn.Name)
		}
	}
	if len(x.OS.Matches) > 0 {
		m := x.OS.Matches[0] // nmap orders by accuracy
		g := &model.OSGuess{Name: m.Name}
		g.Accuracy, _ = strconv.Atoi(m.Accuracy)
		if len(m.Classes) > 0 {
			g.Family = normalizeFamily(m.Classes[0].Family, m.Name)
			if len(m.Classes[0].CPEs) > 0 {
				g.CPE = m.Classes[0].CPEs[0]
			}
		} else {
			g.Family = normalizeFamily("", m.Name)
		}
		h.OS = g
	}
	if len(x.Ports) > maxPortsPerHost {
		return h, fmt.Errorf("host %s reports %d ports (limit %d)", h.Address, len(x.Ports), maxPortsPerHost)
	}
	for _, xp := range x.Ports {
		n, err := strconv.Atoi(xp.ID)
		if err != nil || n < 0 || n > 65535 {
			continue
		}
		p := model.Port{Number: n, Proto: xp.Proto, State: xp.State.State}
		p.Service = model.Service{
			Name: xp.Service.Name, Product: xp.Service.Product, Version: xp.Service.Version,
			ExtraInfo: xp.Service.Extra, Tunnel: xp.Service.Tunnel, CPEs: xp.Service.CPEs,
		}
		for _, s := range xp.Scripts {
			p.Scripts = append(p.Scripts, model.Script{ID: s.ID, Output: s.Output})
			if s.ID == "banner" && p.Service.Banner == "" {
				p.Service.Banner = s.Output
			}
		}
		p.TLS = extractTLS(xp.Scripts)
		h.Ports = append(h.Ports, p)
	}
	return h, nil
}

func normalizeFamily(osfamily, name string) string {
	s := strings.ToLower(osfamily + " " + name)
	switch {
	case strings.Contains(s, "windows"):
		return "windows"
	case strings.Contains(s, "mac os") || strings.Contains(s, "macos") || strings.Contains(s, "ios") || strings.Contains(s, "darwin") || strings.Contains(s, "apple"):
		return "macos"
	case strings.Contains(s, "linux") || strings.Contains(s, "unix") || strings.Contains(s, "bsd"):
		return "linux"
	}
	return "other"
}
