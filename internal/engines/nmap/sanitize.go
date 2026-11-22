package nmap

import (
	"io"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// sanitizer wraps Nmap's XML so Go's strict decoder cannot be derailed by
// attacker-controlled banner bytes. Nmap can emit numeric character references
// to code points XML 1.0 forbids (e.g. &#x1;) and, in some versions, raw invalid
// UTF-8. Either makes encoding/xml abort the whole document, which would let a
// hostile service blind the scanner. We replace both with '?'.
//
// It is streaming: it holds back only a short tail that might be an incomplete
// character reference or a split multi-byte rune.
type sanitizer struct {
	r    io.Reader
	in   []byte // raw read buffer
	out  []byte // sanitized, ready to hand out
	tail []byte // carried-over incomplete suffix
	eof  bool
}

var charRef = regexp.MustCompile(`&#([xX][0-9a-fA-F]+|[0-9]+);`)

func newSanitizer(r io.Reader) io.Reader {
	return &sanitizer{r: r, in: make([]byte, 32<<10)}
}

func (s *sanitizer) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.eof {
			return 0, io.EOF
		}
		n, err := s.r.Read(s.in)
		buf := append(s.tail, s.in[:n]...)
		s.tail = nil
		if err != nil {
			if err != io.EOF {
				return 0, err
			}
			s.eof = true
		}
		if !s.eof {
			buf, s.tail = splitIncomplete(buf)
		}
		s.out = clean(buf)
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

// splitIncomplete separates a trailing partial "&#...;" or partial UTF-8 rune.
func splitIncomplete(b []byte) (head, tail []byte) {
	// partial char ref: last '&' within 12 bytes with no ';' after it
	for i := len(b) - 1; i >= 0 && i >= len(b)-12; i-- {
		if b[i] == ';' {
			break
		}
		if b[i] == '&' {
			return b[:i], append([]byte(nil), b[i:]...)
		}
	}
	// partial multibyte rune at the end
	for i := 1; i <= 3 && i <= len(b); i++ {
		c := b[len(b)-i]
		if c < 0x80 {
			break
		}
		if c >= 0xC0 { // start byte
			if !utf8.FullRune(b[len(b)-i:]) {
				return b[:len(b)-i], append([]byte(nil), b[len(b)-i:]...)
			}
			break
		}
	}
	return b, nil
}

func clean(b []byte) []byte {
	if !utf8.Valid(b) {
		b = replaceInvalidUTF8(b)
	}
	for i, c := range b { // raw control bytes are illegal in XML 1.0
		if c < 0x20 && c != 0x9 && c != 0xA && c != 0xD {
			b[i] = '?'
		}
	}
	return charRef.ReplaceAllFunc(b, func(m []byte) []byte {
		body := m[2 : len(m)-1]
		var v int64
		var err error
		if body[0] == 'x' || body[0] == 'X' {
			v, err = strconv.ParseInt(string(body[1:]), 16, 32)
		} else {
			v, err = strconv.ParseInt(string(body), 10, 32)
		}
		if err != nil || !validXMLChar(rune(v)) {
			return []byte("?")
		}
		return m
	})
}

func replaceInvalidUTF8(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			out = append(out, '?')
		} else {
			out = append(out, b[:size]...)
		}
		b = b[size:]
	}
	return out
}

// validXMLChar implements the XML 1.0 Char production.
func validXMLChar(r rune) bool {
	return r == 0x9 || r == 0xA || r == 0xD ||
		(r >= 0x20 && r <= 0xD7FF) ||
		(r >= 0xE000 && r <= 0xFFFD) ||
		(r >= 0x10000 && r <= 0x10FFFF)
}
