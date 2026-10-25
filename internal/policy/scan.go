package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Vulnerability struct{ VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity string }
type Report struct {
	SchemaVersion int
	Metadata      struct{ ImageID string }
	Results       []struct {
		Target, Type    string
		Vulnerabilities []Vulnerability
		Packages        []struct{ Name, Version string }
	}
}
type Exception struct {
	ID       string `json:"id"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Digest   string `json:"digest"`
	Created  string `json:"created"`
	Expires  string `json:"expires"`
	Owner    string `json:"owner"`
	Reason   string `json:"reason"`
	Evidence string `json:"evidence"`
}
type Exceptions struct {
	SchemaVersion int         `json:"schemaVersion"`
	Entries       []Exception `json:"entries"`
}

var sha256 = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func DecodeExceptions(raw []byte) (Exceptions, error) {
	var e Exceptions
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return e, fmt.Errorf("trailing exception data")
	}
	return e, nil
}

// Scan fails closed on missing inventory, unknown severity, stale exceptions and digest mismatch.
// Only HIGH findings can be excepted. CRITICAL and UNKNOWN always block.
func Scan(report Report, exceptions Exceptions, imageID, subject, evidenceRoot string, now time.Time) ([]string, []string) {
	var blocked, accepted []string
	if report.SchemaVersion != 2 || !sha256.MatchString(imageID) || report.Metadata.ImageID != imageID || !sha256.MatchString(subject) {
		blocked = append(blocked, "SCAN-IDENTITY")
	}
	if exceptions.SchemaVersion != 1 || exceptions.Entries == nil {
		blocked = append(blocked, "EXCEPTION-SCHEMA")
	}
	inventory := false
	for _, r := range report.Results {
		if r.Type == "gobinary" {
			for _, p := range r.Packages {
				if p.Name == "stdlib" && p.Version != "" {
					inventory = true
				}
			}
		}
	}
	if !inventory {
		blocked = append(blocked, "SCAN-INVENTORY")
	}
	valid := map[string]int{}
	used := map[int]bool{}
	for i, e := range exceptions.Entries {
		created, cerr := time.Parse(time.RFC3339, e.Created)
		expires, eerr := time.Parse(time.RFC3339, e.Expires)
		key := e.ID + "|" + e.Package + "|" + e.Version
		_, dup := valid[key]
		ok := cerr == nil && eerr == nil && !created.After(now) && expires.After(now) && expires.After(created) && expires.Sub(created) <= 14*24*time.Hour
		ok = ok && e.Digest == subject && e.ID != "" && e.Package != "" && e.Version != "" && len(strings.TrimSpace(e.Owner)) > 0 && len(strings.TrimSpace(e.Reason)) >= 40 && !dup
		clean := filepath.Clean(e.Evidence)
		ok = ok && !filepath.IsAbs(clean) && strings.HasPrefix(filepath.ToSlash(clean), "docs/exceptions/") && !strings.Contains(clean, "..")
		resolved, err := filepath.EvalSymlinks(filepath.Join(evidenceRoot, clean))
		root, _ := filepath.EvalSymlinks(evidenceRoot)
		root, _ = filepath.Abs(root)
		absolute, _ := filepath.Abs(resolved)
		ok = ok && err == nil && strings.HasPrefix(absolute, root+string(filepath.Separator))
		data, err := os.ReadFile(resolved)
		ok = ok && err == nil && len(strings.TrimSpace(string(data))) >= 80
		if !ok {
			blocked = append(blocked, "EXCEPTION-INVALID:"+key)
			continue
		}
		valid[key] = i
	}
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			key := v.VulnerabilityID + "|" + v.PkgName + "|" + v.InstalledVersion
			if v.VulnerabilityID == "" || v.PkgName == "" || v.InstalledVersion == "" {
				blocked = append(blocked, "SCAN-MALFORMED-FINDING")
				continue
			}
			switch v.Severity {
			case "LOW", "MEDIUM":
			case "HIGH":
				if i, ok := valid[key]; ok {
					used[i] = true
					accepted = append(accepted, "EXCEPTION:"+key)
				} else {
					blocked = append(blocked, "HIGH:"+key)
				}
			default:
				blocked = append(blocked, v.Severity+":"+key)
			}
		}
	}
	for _, i := range valid {
		if !used[i] {
			blocked = append(blocked, "EXCEPTION-UNUSED:"+exceptions.Entries[i].ID)
		}
	}
	return blocked, accepted
}
