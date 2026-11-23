package intel

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"babylon/internal/store"
)

// KEVURL is CISA's official catalogue.
const KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// ParseKEV reads CISA's KEV JSON catalogue.
func ParseKEV(r io.Reader) (entries []store.KEVEntry, version string, err error) {
	var doc struct {
		CatalogVersion  string `json:"catalogVersion"`
		Vulnerabilities []struct {
			CVE        string `json:"cveID"`
			Vendor     string `json:"vendorProject"`
			Product    string `json:"product"`
			Name       string `json:"vulnerabilityName"`
			DateAdded  string `json:"dateAdded"`
			DueDate    string `json:"dueDate"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
			Notes      string `json:"notes"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(r, 256<<20)).Decode(&doc); err != nil {
		return nil, "", fmt.Errorf("parse KEV: %w", err)
	}
	for _, v := range doc.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVE))
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		entries = append(entries, store.KEVEntry{CVE: id, Vendor: v.Vendor, Product: v.Product, Name: v.Name,
			DateAdded: v.DateAdded, DueDate: v.DueDate, Ransomware: v.Ransomware, Notes: v.Notes})
	}
	if len(entries) == 0 {
		return nil, "", fmt.Errorf("KEV catalogue contained no entries; refusing to replace existing data")
	}
	return entries, doc.CatalogVersion, nil
}
