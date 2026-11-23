package lab

import (
	"strings"
	"testing"

	"babylon/internal/store"
)

const sample = `
version: 2
thresholds: {min_recall: 0.75, max_forbidden: 0}
expected:
  - {id: redis-noauth, port: 16379, title: "redis.*without auth", min_confidence: confirmed}
  - {id: apache-cve, port: 18081, cve: CVE-2021-41773, min_confidence: tentative}
  - {id: ssh-weak, port: 12222, title: "weak algorithms", min_confidence: confirmed}
  - {id: needs-active, port: 2375, title: docker, needs: allow-active}
forbidden:
  - {id: nse-fp, port: 18082, title: "cve2011-3192", reason: Apache-only CVE on nginx}
`

func rows() []store.FindingRow {
	return []store.FindingRow{
		{ID: 1, Address: "127.0.0.1", Port: 16379, Title: "Redis accessible without authentication", Confidence: "confirmed", Severity: "high"},
		{ID: 2, Address: "127.0.0.1", Port: 18081, Title: "Apache 2.4.49 CVE", CVEs: []string{"CVE-2021-41773"}, Confidence: "tentative", Severity: "high"},
		{ID: 3, Address: "127.0.0.1", Port: 12222, Title: "SSH server supports weak algorithms", Confidence: "firm", Severity: "medium"},
		{ID: 4, Address: "127.0.0.1", Port: 9999, Title: "Something unreviewed", Confidence: "confirmed", Severity: "critical"},
	}
}

func TestParseRejectsBadManifests(t *testing.T) {
	for name, y := range map[string]string{
		"version":   "version: 1\n",
		"unknown":   "version: 2\nwat: 1\n",
		"dup":       "version: 2\nexpected:\n - {id: a, port: 1}\n - {id: a, port: 2}\n",
		"empty":     "version: 2\nexpected:\n - {id: a}\n",
		"regexp":    "version: 2\nexpected:\n - {id: a, title: \"(\"}\n",
		"forbidden": "version: 2\nforbidden:\n - {id: f}\n",
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestEvaluateRecallWeakAndForbidden(t *testing.T) {
	m, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	r := Evaluate(m, rows(), Options{})
	st := map[string]string{}
	for _, o := range r.Outcomes {
		st[o.ID] = o.Status
	}
	if st["redis-noauth"] != "hit" || st["apache-cve"] != "hit" || st["ssh-weak"] != "weak" || st["needs-active"] != "skipped" {
		t.Fatalf("%v", st)
	}
	// firm is below the required confirmed, so it is a weak hit and does not count.
	if r.Expected != 3 || r.Hits != 2 || r.Skipped != 1 {
		t.Fatalf("%+v", r)
	}
	if r.Pass || len(r.Failures) != 1 || !strings.Contains(r.Failures[0], "recall 67%") {
		t.Fatalf("2/3 is below 75%%: %+v", r)
	}
	if r.Unreviewed != 1 || !strings.Contains(r.UnreviewedList[0], "unreviewed") {
		t.Fatalf("%+v", r.UnreviewedList)
	}

	// A forbidden finding fails the run even at full recall.
	good := rows()
	good[2].Confidence = "confirmed"
	good = append(good, store.FindingRow{ID: 5, Address: "127.0.0.1", Port: 18082, Title: "http-vuln-cve2011-3192", Confidence: "firm", Severity: "high"})
	r = Evaluate(m, good, Options{})
	if r.Recall != 1 || r.Pass || len(r.ForbiddenHits) != 1 || !strings.Contains(r.Text(), "FALSE POSITIVE") {
		t.Fatalf("%+v", r)
	}
	// Capabilities turn on skipped expectations.
	r = Evaluate(m, good[:3], Options{Capabilities: map[string]bool{"allow-active": true}})
	if r.Expected != 4 || r.Outcomes[3].Status != "miss" {
		t.Fatalf("%+v", r.Outcomes)
	}
}

func TestPassWhenEverythingFound(t *testing.T) {
	m, _ := Parse([]byte(sample))
	g := rows()[:3]
	g[2].Confidence = "confirmed"
	r := Evaluate(m, g, Options{})
	if !r.Pass || !strings.Contains(r.Text(), "RESULT: PASS") {
		t.Fatalf("%s", r.Text())
	}
}
