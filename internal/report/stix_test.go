package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vsm/internal/analyze"
	"vsm/internal/netmon"
	"vsm/internal/snapshot"
)

func TestWriteSTIXProducesValidBundle(t *testing.T) {
	r := &SessionReport{
		Version:     "test",
		SandboxDir:  `C:\sb`,
		GeneratedAt: time.Now(),
		Target:      TargetInfo{Path: `C:\sample.exe`, SHA256: "a1b2c3"},
		Analysis:    analyze.Result{Level: "dangerous"},
		FSChanges: []snapshot.FSChange{{
			Type:  snapshot.Added,
			Path:  `C:\sb\appdata\drop.exe`,
			After: &snapshot.FileEntry{SHA256: "deadbeef"},
		}},
		Network: []netmon.Conn{{
			Proto: "TCP", RemoteAddr: "8.8.8.8", RemotePort: 443, Host: "dns.google.",
		}},
		RegChanges: []snapshot.RegChange{{
			Type:      snapshot.Added,
			KeyPath:   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
			ValueName: "Evil",
		}},
	}
	path := filepath.Join(t.TempDir(), "iocs.stix.json")
	if err := r.WriteSTIX(path); err != nil {
		t.Fatalf("WriteSTIX: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Type    string           `json:"type"`
		ID      string           `json:"id"`
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("STIX bundle is not valid JSON: %v", err)
	}
	if bundle.Type != "bundle" {
		t.Errorf("type = %q, want bundle", bundle.Type)
	}

	kinds := map[string]int{}
	for _, o := range bundle.Objects {
		kinds[o["type"].(string)]++
	}
	if kinds["file"] != 2 {
		t.Errorf("file objects = %d, want 2 (target + dropped)", kinds["file"])
	}
	if kinds["ipv4-addr"] != 1 {
		t.Errorf("ipv4-addr objects = %d, want 1", kinds["ipv4-addr"])
	}
	if kinds["domain-name"] != 1 {
		t.Errorf("domain-name objects = %d, want 1", kinds["domain-name"])
	}
	if kinds["windows-registry-key"] != 1 {
		t.Errorf("windows-registry-key objects = %d, want 1", kinds["windows-registry-key"])
	}
	if kinds["report"] != 1 {
		t.Errorf("report SDO = %d, want 1", kinds["report"])
	}
}

func TestWriteSTIXEmptyIsValid(t *testing.T) {
	r := &SessionReport{GeneratedAt: time.Now(), Target: TargetInfo{Path: `C:\x.exe`}}
	path := filepath.Join(t.TempDir(), "iocs.stix.json")
	if err := r.WriteSTIX(path); err != nil {
		t.Fatalf("WriteSTIX (empty): %v", err)
	}
	data, _ := os.ReadFile(path)
	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("empty STIX bundle is not valid JSON: %v", err)
	}
	if bundle["type"] != "bundle" {
		t.Error("empty bundle must still be a valid STIX bundle")
	}
}

func TestStixRegKey(t *testing.T) {
	got := stixRegKey(`hkcu\Software\Run`)
	if want := `HKEY_CURRENT_USER\Software\Run`; got != want {
		t.Errorf("stixRegKey = %q, want %q", got, want)
	}
}
