package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"babylon/internal/model"
	"babylon/internal/store"
)

func seed(t *testing.T) (*store.Store, int64) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	id, _ := st.CreateScan(ctx, "Quarterly *scan*", "basic", []string{"10.0.0.0/24"}, map[string]any{})
	st.IngestHost(ctx, id, model.Host{Address: "10.0.0.5", State: "up", OS: &model.OSGuess{Name: "Linux 5"}, Ports: []model.Port{
		{Number: 443, Proto: "tcp", State: "open", Service: model.Service{Name: "http", Product: "nginx", Version: "1.16.0"},
			TLS: &model.TLS{Weak: []string{"TLSv1.0 is enabled (deprecated protocol)"}}}}})
	cvss := 9.8
	st.RecordFinding(ctx, id, model.Finding{Fingerprint: "a", Address: "10.0.0.5", Port: 443, Proto: "tcp", Title: "Critical bug", Severity: "critical",
		CVSS: &cvss, CVEs: []string{"CVE-2021-1"}, Confidence: model.ConfConfirmed, Engine: "nuclei", EngineRef: "a", Remediation: "Upgrade", Evidence: "proof with ``` fence"})
	st.RecordFinding(ctx, id, model.Finding{Fingerprint: "b", Address: "10.0.0.5", Port: 443, Proto: "tcp", Title: "=HYPERLINK(\"http://evil\")", Severity: "medium",
		Confidence: model.ConfTentative, Detection: "version", Engine: "nuclei", EngineRef: "b", Remediation: "@SUM(A1)", Description: "<script>alert(1)</script> [x](javascript:alert(1))"})
	st.RecordFinding(ctx, id, model.Finding{Fingerprint: "c", Address: "10.0.0.5", Title: "Detected nginx", Severity: "info", Confidence: model.ConfConfirmed, Engine: "nuclei", EngineRef: "c"})
	st.RecordCheckRun(ctx, id, 1, "redis-unauth", "skipped", "no redis-info result")
	return st, id
}

func TestBuildAccuracyFiltersViewNotData(t *testing.T) {
	st, id := seed(t)
	normal, err := Build(context.Background(), st, id, "normal")
	if err != nil {
		t.Fatal(err)
	}
	avoid, _ := Build(context.Background(), st, id, "avoid-false-alarms")
	if len(normal.Findings) != 3 || len(avoid.Findings) != 2 {
		t.Fatalf("normal=%d avoid=%d findings", len(normal.Findings), len(avoid.Findings))
	}
	if avoid.Summary.Possible != 1 || !avoid.Summary.PossibleHidden || avoid.Summary.Verified != 1 || avoid.Summary.Informational != 1 {
		t.Fatalf("summary=%+v", avoid.Summary)
	}
	// Hiding never deletes: the same data is still there.
	if again, _ := Build(context.Background(), st, id, "normal"); len(again.Findings) != 3 {
		t.Fatal("accuracy filtering must not remove stored findings")
	}
	if len(normal.Hosts) != 1 || normal.Hosts[0].Services[0].Product != "nginx" || len(normal.Hosts[0].Services[0].TLSWeak) != 1 {
		t.Fatalf("hosts=%+v", normal.Hosts)
	}
	if normal.Coverage.CheckRuns["skipped"] != 1 || len(normal.Coverage.Skipped) != 1 {
		t.Fatalf("coverage=%+v", normal.Coverage)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	st, id := seed(t)
	r, _ := Build(context.Background(), st, id, "normal")
	var buf bytes.Buffer
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil || back.SchemaVersion != SchemaVersion || len(back.Findings) != 3 {
		t.Fatalf("err=%v back=%+v", err, back.Summary)
	}
}

func TestMarkdownNeutralizesHostileContent(t *testing.T) {
	st, id := seed(t)
	r, _ := Build(context.Background(), st, id, "normal")
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	if strings.Contains(md, "<script>") {
		t.Error("raw <script> leaked into markdown")
	}
	if strings.Contains(md, "[x](javascript:") {
		t.Error("markdown link with javascript: URL leaked")
	}
	if !strings.Contains(md, "Quarterly \\*scan\\*") {
		t.Error("scan name must be escaped")
	}
	// Evidence containing ``` must be wrapped in a longer fence.
	if !strings.Contains(md, "````\nproof with ``` fence\n````") {
		t.Errorf("evidence fence too short:\n%s", md)
	}
	for _, want := range []string{"## Executive summary", "| critical | 1 |", "## Possible findings (version-based, unverified)", "## Coverage", "redis-unauth"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	// Severity ordering: the critical finding comes before the possible one.
	if strings.Index(md, "Critical bug") > strings.Index(md, "Possible findings") {
		t.Error("verified findings must precede possible ones")
	}
}

func TestCSVNeutralizesFormulas(t *testing.T) {
	st, id := seed(t)
	r, _ := Build(context.Background(), st, id, "normal")
	var buf bytes.Buffer
	if err := WriteCSV(&buf, r); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(rows) != 4 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if cell != "" && strings.ContainsAny(cell[:1], "=+-@") {
				t.Errorf("formula-capable cell not neutralized: %q", cell)
			}
		}
	}
	if rows[1][0] != "critical" {
		t.Errorf("csv must be severity-sorted, first row=%v", rows[1])
	}
}
