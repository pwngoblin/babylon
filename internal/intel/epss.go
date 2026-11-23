package intel

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"strconv"
	"strings"

	"babylon/internal/store"
)

// EPSSURL is FIRST's daily score file.
const EPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// ParseEPSS reads the (optionally gzipped) EPSS CSV. The first line is a
// comment carrying the model version and score date.
func ParseEPSS(r io.Reader) (entries []store.EPSSEntry, asOf string, err error) {
	br := bufio.NewReaderSize(r, 1<<20)
	if magic, e := br.Peek(2); e == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, e := gzip.NewReader(br)
		if e != nil {
			return nil, "", e
		}
		defer gz.Close()
		br = bufio.NewReaderSize(gz, 1<<20)
	}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	header := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			for _, part := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
				if k, v, ok := strings.Cut(part, ":"); ok && strings.TrimSpace(k) == "score_date" {
					asOf = strings.TrimSpace(v)
				}
			}
			continue
		}
		if !header {
			if !strings.HasPrefix(strings.ToLower(line), "cve,") {
				return nil, "", fmt.Errorf("unexpected EPSS header %q", line)
			}
			header = true
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 3 {
			continue
		}
		score, e1 := strconv.ParseFloat(f[1], 64)
		pct, e2 := strconv.ParseFloat(f[2], 64)
		if e1 != nil || e2 != nil || score < 0 || score > 1 || pct < 0 || pct > 1 {
			continue
		}
		entries = append(entries, store.EPSSEntry{CVE: f[0], Score: score, Percentile: pct})
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	if len(entries) == 0 {
		return nil, "", fmt.Errorf("EPSS file contained no scores; refusing to replace existing data")
	}
	return entries, asOf, nil
}
