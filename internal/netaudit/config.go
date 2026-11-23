// Package netaudit audits network-device configuration text (Cisco IOS and IOS-XE
// style) against a hardening baseline. It works on an exported running-config,
// so it needs no connection to the device and can be run on a copy from a backup
// system or a change ticket. Rules are pure functions over the parsed config.
package netaudit

import (
	"bufio"
	"strings"
)

// Config is a parsed IOS-style configuration: top-level commands plus the
// indented blocks (interfaces, lines, routers) under their header line.
type Config struct {
	Top    []string // top-level lines, trimmed, comments and blanks removed
	Blocks []Block
}

// Block is a header line such as "line vty 0 4" and the indented lines below it.
type Block struct {
	Header string
	Lines  []string
}

// Parse reads configuration text. Comment lines ("!") and blank lines are
// dropped; indentation decides block membership. Windows line endings are fine.
func Parse(text string) *Config {
	c := &Config{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var cur *Block
	for sc.Scan() {
		raw := strings.TrimRight(sc.Text(), " \t\r")
		trim := strings.TrimSpace(raw)
		if trim == "" || strings.HasPrefix(trim, "!") {
			if trim == "" || raw == trim {
				cur = nil // "!" at column 0 ends a block
			}
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			if cur != nil {
				cur.Lines = append(cur.Lines, trim)
			}
			continue
		}
		c.Top = append(c.Top, trim)
		c.Blocks = append(c.Blocks, Block{Header: trim})
		cur = &c.Blocks[len(c.Blocks)-1]
	}
	return c
}

// Has reports whether a top-level line equals cmd or starts with it followed by a space.
func (c *Config) Has(cmd string) bool { return len(c.Find(cmd)) > 0 }

// Find returns top-level lines equal to cmd or starting with "cmd ".
func (c *Config) Find(cmd string) []string {
	var out []string
	for _, l := range c.Top {
		if l == cmd || strings.HasPrefix(l, cmd+" ") {
			out = append(out, l)
		}
	}
	return out
}

// BlocksWith returns blocks whose header starts with prefix.
func (c *Config) BlocksWith(prefix string) []Block {
	var out []Block
	for _, b := range c.Blocks {
		if b.Header == prefix || strings.HasPrefix(b.Header, prefix+" ") {
			out = append(out, b)
		}
	}
	return out
}

// Has reports whether a block contains a line equal to cmd or starting with "cmd ".
func (b Block) Has(cmd string) bool { return len(b.Find(cmd)) > 0 }

// Find returns the block's lines equal to cmd or starting with "cmd ".
func (b Block) Find(cmd string) []string {
	var out []string
	for _, l := range b.Lines {
		if l == cmd || strings.HasPrefix(l, cmd+" ") {
			out = append(out, l)
		}
	}
	return out
}
