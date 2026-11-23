// Package notify tells people about change: after a scan it reports only what is
// new since the previous scan of the same targets, so a scheduled scan is quiet
// unless something needs attention. The webhook URL is a secret (chat webhooks
// embed a token), so the config file must not be readable by other users.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"babylon/internal/model"
	"babylon/internal/store"
)

// Config is ~/.babylon/notify.yaml.
type Config struct {
	Webhook struct {
		URL    string `yaml:"url"`
		Format string `yaml:"format"` // slack (default, also Teams/Mattermost: {"text":...}) or json
	} `yaml:"webhook"`
	MinSeverity string `yaml:"min_severity"` // default high
	AlwaysKEV   *bool  `yaml:"always_kev"`   // default true: a known-exploited finding always notifies
	MaxListed   int    `yaml:"max_listed"`   // default 10
}

// Load reads the config from home. A missing file means notifications are off
// (nil, nil); a present but unusable one is an error so it is never silently ignored.
func Load(home string) (*Config, error) {
	path := filepath.Join(home, "notify.yaml")
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users and holds a secret URL: chmod 600 it", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, c.validate()
}

func (c *Config) validate() error {
	u, err := url.Parse(c.Webhook.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("webhook.url must be an http(s) URL")
	}
	switch c.Webhook.Format {
	case "":
		c.Webhook.Format = "slack"
	case "slack", "json":
	default:
		return fmt.Errorf("webhook.format must be slack or json")
	}
	if c.MinSeverity == "" {
		c.MinSeverity = "high"
	}
	if model.SeverityRank(c.MinSeverity) == 0 {
		return fmt.Errorf("min_severity must be info, low, medium, high or critical")
	}
	if c.MaxListed <= 0 {
		c.MaxListed = 10
	}
	return nil
}

func (c *Config) alwaysKEV() bool { return c.AlwaysKEV == nil || *c.AlwaysKEV }

// Item is one finding in a notification.
type Item struct {
	ID       int64  `json:"id"`
	Severity string `json:"severity"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Title    string `json:"title"`
	KEV      bool   `json:"kev,omitempty"`
}

// Message is what gets sent.
type Message struct {
	ScanID   int64    `json:"scan_id"`
	Targets  []string `json:"targets"`
	New      []Item   `json:"new"`       // notifiable new findings, most urgent first, capped
	NewTotal int      `json:"new_total"` // notifiable new findings before the cap
	Resolved int      `json:"resolved"`
	Text     string   `json:"text"`
}

// Build selects what is worth a notification from a diff. It returns nil when
// nothing is: no message is sent for a quiet scan.
func (c *Config) Build(scanID int64, targets []string, d store.ScanDiff) *Message {
	min := model.SeverityRank(c.MinSeverity)
	var items []Item
	for _, f := range d.New {
		if f.Triage != nil && f.Triage.Active {
			continue
		}
		if f.Severity == "info" || f.Confidence == model.ConfTentative && !f.KEV {
			continue // a guess is not worth waking someone for
		}
		if model.SeverityRank(f.Severity) >= min || (c.alwaysKEV() && f.KEV) {
			items = append(items, Item{ID: f.ID, Severity: f.Severity, Host: f.Address, Port: f.Port, Title: f.Title, KEV: f.KEV})
		}
	}
	if len(items) == 0 {
		return nil
	}
	sortItems(items)
	m := &Message{ScanID: scanID, Targets: targets, NewTotal: len(items), Resolved: len(d.Resolved)}
	m.New = items
	if len(m.New) > c.MaxListed {
		m.New = m.New[:c.MaxListed]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Babylon scan %d (%s): %d new finding(s) need attention", scanID, strings.Join(targets, ", "), len(items))
	if m.Resolved > 0 {
		fmt.Fprintf(&b, ", %d resolved", m.Resolved)
	}
	b.WriteString("\n")
	for _, it := range m.New {
		where := it.Host
		if it.Port != 0 {
			where = fmt.Sprintf("%s:%d", it.Host, it.Port)
		}
		kev := ""
		if it.KEV {
			kev = " [KEV]"
		}
		fmt.Fprintf(&b, "- %s %s: %s%s (finding #%d)\n", strings.ToUpper(it.Severity), where, clean(it.Title), kev, it.ID)
	}
	if len(items) > len(m.New) {
		fmt.Fprintf(&b, "...and %d more. Run: babylon scans show %d\n", len(items)-len(m.New), scanID)
	}
	m.Text = b.String()
	return m
}

func sortItems(items []Item) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && less(items[j], items[j-1]); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func less(a, b Item) bool {
	if a.KEV != b.KEV {
		return a.KEV
	}
	if ra, rb := model.SeverityRank(a.Severity), model.SeverityRank(b.Severity); ra != rb {
		return ra > rb
	}
	return a.ID < b.ID
}

// clean strips line breaks and control characters from scanned text before it
// goes into a chat message.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// Send posts the message. The URL is never included in errors.
func (c *Config) Send(ctx context.Context, m *Message) error {
	var body []byte
	if c.Webhook.Format == "json" {
		body, _ = json.Marshal(m)
	} else {
		body, _ = json.Marshal(map[string]string{"text": m.Text})
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Webhook.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: invalid URL")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return fmt.Errorf("webhook delivery failed: %s", redactURL(err.Error(), c.Webhook.URL))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook answered HTTP %d", resp.StatusCode)
	}
	return nil
}

func redactURL(msg, u string) string { return strings.ReplaceAll(msg, u, "<webhook url>") }
