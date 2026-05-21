package report

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vsm/internal/snapshot"
)

// WriteSTIX writes the observed indicators as a STIX 2.1 bundle. STIX is the
// standard interchange format for cyber-threat intelligence and is imported
// by MISP and most threat-intel platforms, so the bundle lets a VSM finding
// be shared and correlated automatically.
//
// WriteSTIX сохраняет обнаружённые индикаторы как STIX 2.1 bundle. STIX —
// стандартный формат обмена данными о киберугрозах, его импортируют MISP и
// большинство threat-intel платформ, поэтому результат анализа VSM можно
// автоматически передавать и сопоставлять.
func (r *SessionReport) WriteSTIX(path string) error {
	var objects []map[string]any
	var refs []string

	add := func(o map[string]any) {
		objects = append(objects, o)
		refs = append(refs, o["id"].(string))
	}

	// The analysed target itself.
	if r.Target.SHA256 != "" {
		add(map[string]any{
			"type":   "file",
			"id":     "file--" + newUUID(),
			"name":   filepath.Base(r.Target.Path),
			"hashes": map[string]string{"SHA-256": r.Target.SHA256},
		})
	}

	// Files the program created inside the sandbox (its own footprint).
	for _, c := range r.FSChanges {
		if c.Type != snapshot.Added || c.After == nil || !r.InSandbox(c.Path) {
			continue
		}
		o := map[string]any{
			"type": "file",
			"id":   "file--" + newUUID(),
			"name": filepath.Base(c.Path),
		}
		if c.After.SHA256 != "" {
			o["hashes"] = map[string]string{"SHA-256": c.After.SHA256}
		}
		add(o)
	}

	// External network endpoints and resolved domains.
	seen := map[string]bool{}
	for _, c := range r.Network {
		if !isExternalIP(c.RemoteAddr) {
			continue
		}
		if !seen["ip:"+c.RemoteAddr] {
			seen["ip:"+c.RemoteAddr] = true
			kind := "ipv4-addr"
			if strings.Contains(c.RemoteAddr, ":") {
				kind = "ipv6-addr"
			}
			add(map[string]any{
				"type":  kind,
				"id":    kind + "--" + newUUID(),
				"value": c.RemoteAddr,
			})
		}
		if c.Host != "" {
			d := strings.TrimRight(c.Host, ".")
			if !seen["dom:"+d] {
				seen["dom:"+d] = true
				add(map[string]any{
					"type":  "domain-name",
					"id":    "domain-name--" + newUUID(),
					"value": d,
				})
			}
		}
	}

	// Registry autorun entries.
	for _, c := range r.RegChanges {
		if c.Type == snapshot.Deleted {
			continue
		}
		k := strings.ToLower(c.KeyPath)
		if strings.Contains(k, `currentversion\run`) || strings.Contains(k, "winlogon") {
			add(map[string]any{
				"type": "windows-registry-key",
				"id":   "windows-registry-key--" + newUUID(),
				"key":  stixRegKey(c.KeyPath),
			})
		}
	}

	bundle := map[string]any{
		"type": "bundle",
		"id":   "bundle--" + newUUID(),
	}

	all := make([]map[string]any, 0, len(objects)+1)
	// A STIX report SDO ties the observables together; object_refs must be
	// non-empty, so the report is only emitted when something was observed.
	if len(refs) > 0 {
		now := r.GeneratedAt.UTC().Format(time.RFC3339)
		all = append(all, map[string]any{
			"type":         "report",
			"spec_version": "2.1",
			"id":           "report--" + newUUID(),
			"created":      now,
			"modified":     now,
			"published":    now,
			"name":         "VSM analysis: " + filepath.Base(r.Target.Path),
			"description":  "Verdict: " + r.Analysis.Level,
			"report_types": []string{"malware"},
			"object_refs":  refs,
		})
	}
	all = append(all, objects...)
	bundle["objects"] = all

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// stixRegKey rewrites a registry path to the hive form STIX expects.
func stixRegKey(k string) string {
	low := strings.ToLower(k)
	switch {
	case strings.HasPrefix(low, `hkcu\`):
		return `HKEY_CURRENT_USER\` + k[5:]
	case strings.HasPrefix(low, `hklm\`):
		return `HKEY_LOCAL_MACHINE\` + k[5:]
	case strings.HasPrefix(low, `hkcr\`):
		return `HKEY_CLASSES_ROOT\` + k[5:]
	case strings.HasPrefix(low, `hku\`):
		return `HKEY_USERS\` + k[4:]
	default:
		return k
	}
}

// newUUID returns a random RFC 4122 version-4 UUID.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
