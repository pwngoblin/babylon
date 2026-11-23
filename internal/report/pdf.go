package report

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// PDFRenderer is an external program able to turn the HTML report into a PDF.
type PDFRenderer struct {
	Name string
	Path string
}

var chromeNames = []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "microsoft-edge"}

var chromeMacApps = []string{
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
	"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
}

// FindPDFRenderer returns the first usable renderer: headless Chrome-family
// browsers first, then weasyprint. nil means PDF export is unavailable.
func FindPDFRenderer() *PDFRenderer {
	for _, n := range chromeNames {
		if p, err := exec.LookPath(n); err == nil {
			return &PDFRenderer{n, p}
		}
	}
	for _, p := range chromeMacApps {
		if _, err := os.Stat(p); err == nil {
			return &PDFRenderer{"chrome", p}
		}
	}
	if p, err := exec.LookPath("weasyprint"); err == nil {
		return &PDFRenderer{"weasyprint", p}
	}
	return nil
}

var ErrNoPDF = errors.New("no PDF renderer found (install Chrome/Chromium or weasyprint); use --format html and print to PDF from a browser")

// RenderPDF writes the report as a PDF to outPath. The HTML is rendered from a
// private temp directory; the renderer gets no network access requirement as
// the report is self-contained.
func RenderPDF(ctx context.Context, r *Report, outPath string) error {
	rd := FindPDFRenderer()
	if rd == nil {
		return ErrNoPDF
	}
	dir, err := os.MkdirTemp("", "babylon-pdf-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	htmlPath := filepath.Join(dir, "report.html")
	f, err := os.OpenFile(htmlPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := WriteHTML(f, r); err != nil {
		f.Close()
		return err
	}
	f.Close()
	abs, err := filepath.Abs(outPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if rd.Name == "weasyprint" {
		cmd = exec.CommandContext(ctx, rd.Path, htmlPath, abs)
	} else {
		cmd = exec.CommandContext(ctx, rd.Path, "--headless", "--disable-gpu", "--no-sandbox",
			"--user-data-dir="+filepath.Join(dir, "profile"), "--no-pdf-header-footer",
			"--print-to-pdf="+abs, "file://"+htmlPath)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s failed: %v: %.300s", rd.Name, err, out)
	}
	if st, err := os.Stat(abs); err != nil || st.Size() == 0 {
		return fmt.Errorf("%s produced no output", rd.Name)
	}
	return os.Chmod(abs, 0o600)
}
