package report

import (
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
	"time"
)

// WriteNessus writes the scan as a .nessus (NessusClientData_v2) file so results
// can be opened by tools that read Nessus exports. Plugin IDs are Babylon's own
// (9,000,000 and up, derived from the finding title) and never collide with real
// Tenable plugin IDs. Scan data is untrusted, so every string is stripped of
// characters XML cannot carry.

type nessusData struct {
	XMLName xml.Name     `xml:"NessusClientData_v2"`
	Policy  nessusPolicy `xml:"Policy"`
	Report  nessusReport `xml:"Report"`
}

type nessusPolicy struct {
	Name  string   `xml:"policyName"`
	Prefs struct{} `xml:"Preferences"`
}

type nessusReport struct {
	Name  string       `xml:"name,attr"`
	Hosts []nessusHost `xml:"ReportHost"`
}

type nessusHost struct {
	Name  string       `xml:"name,attr"`
	Props []nessusTag  `xml:"HostProperties>tag"`
	Items []nessusItem `xml:"ReportItem"`
}

type nessusTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusItem struct {
	Port        int      `xml:"port,attr"`
	SvcName     string   `xml:"svc_name,attr"`
	Protocol    string   `xml:"protocol,attr"`
	Severity    int      `xml:"severity,attr"`
	PluginID    int      `xml:"pluginID,attr"`
	PluginName  string   `xml:"pluginName,attr"`
	Family      string   `xml:"pluginFamily,attr"`
	CVSS3       string   `xml:"cvss3_base_score,omitempty"`
	Description string   `xml:"description"`
	Synopsis    string   `xml:"synopsis"`
	Solution    string   `xml:"solution"`
	Risk        string   `xml:"risk_factor"`
	Output      string   `xml:"plugin_output,omitempty"`
	CVEs        []string `xml:"cve"`
	Exploited   string   `xml:"exploited_by_nessus,omitempty"`
	KEV         string   `xml:"in_the_news,omitempty"`
}

var nessusSeverity = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func xmlClean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || (r >= 0x20 && r <= 0xD7FF) || (r >= 0xE000 && r <= 0xFFFD) || r >= 0x10000 {
			return r
		}
		return -1
	}, s)
}

// NessusPluginID gives a stable Babylon-range plugin id for a finding title.
func NessusPluginID(title string) int {
	return 9_000_000 + int(crc32.ChecksumIEEE([]byte(title))%900_000)
}

func WriteNessus(w io.Writer, r *Report) error {
	d := nessusData{Policy: nessusPolicy{Name: xmlClean("Babylon " + r.Scan.Template)}}
	name := r.Scan.Name
	if name == "" {
		name = "Babylon scan " + strconv.FormatInt(r.Scan.ID, 10)
	}
	d.Report.Name = xmlClean(name)
	svc := map[string]map[string]string{}
	for _, h := range r.Hosts {
		m := map[string]string{}
		for _, s := range h.Services {
			m[fmt.Sprintf("%d/%s", s.Port, s.Proto)] = s.Name
		}
		svc[h.Address] = m
	}
	byHost := map[string]*nessusHost{}
	var order []string
	host := func(addr string) *nessusHost {
		if h, ok := byHost[addr]; ok {
			return h
		}
		h := &nessusHost{Name: xmlClean(addr), Props: []nessusTag{{Name: "host-ip", Value: xmlClean(addr)}}}
		for _, rh := range r.Hosts {
			if rh.Address == addr {
				if rh.OS != "" {
					h.Props = append(h.Props, nessusTag{Name: "operating-system", Value: xmlClean(rh.OS)})
				}
				if len(rh.Hostnames) > 0 {
					h.Props = append(h.Props, nessusTag{Name: "host-fqdn", Value: xmlClean(rh.Hostnames[0])})
				}
			}
		}
		if r.Scan.StartedAt != "" {
			h.Props = append(h.Props, nessusTag{Name: "HOST_START", Value: xmlClean(r.Scan.StartedAt)})
		}
		if r.Scan.FinishedAt != "" {
			h.Props = append(h.Props, nessusTag{Name: "HOST_END", Value: xmlClean(r.Scan.FinishedAt)})
		}
		byHost[addr] = h
		order = append(order, addr)
		return h
	}
	for _, h := range r.Hosts { // hosts with no findings still appear
		host(h.Address)
	}
	for _, f := range r.Findings {
		it := nessusItem{
			Port: f.Port, Protocol: f.Proto, Severity: nessusSeverity[f.Severity],
			PluginID: NessusPluginID(f.Title), PluginName: xmlClean(f.Title), Family: xmlClean(familyOr(f.Family)),
			Description: xmlClean(f.Description), Synopsis: xmlClean(f.Synopsis), Solution: xmlClean(f.Remediation),
			Risk: riskFactor(f.Severity), Output: xmlClean(f.Evidence),
		}
		if it.Protocol == "" {
			it.Protocol = "tcp"
		}
		it.SvcName = xmlClean(svc[f.Host][fmt.Sprintf("%d/%s", f.Port, it.Protocol)])
		if it.SvcName == "" {
			it.SvcName = "general"
		}
		if f.CVSS != nil {
			it.CVSS3 = strconv.FormatFloat(*f.CVSS, 'f', 1, 64)
		}
		for _, c := range f.CVEs {
			it.CVEs = append(it.CVEs, xmlClean(c))
		}
		if f.KEV {
			it.KEV = "true"
			it.Exploited = "true"
		}
		h := host(f.Host)
		h.Items = append(h.Items, it)
	}
	for _, a := range order {
		d.Report.Hosts = append(d.Report.Hosts, *byHost[a])
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(d); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n<!-- exported by Babylon at "+time.Now().UTC().Format(time.RFC3339)+" -->\n")
	return err
}

func familyOr(f string) string {
	if f == "" {
		return "General"
	}
	return f
}

func riskFactor(sev string) string {
	switch sev {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	}
	return "None"
}
