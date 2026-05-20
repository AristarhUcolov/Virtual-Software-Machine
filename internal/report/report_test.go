package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vsm/internal/analyze"
	"vsm/internal/snapshot"
)

func TestHumanSize(t *testing.T) {
	cases := map[int64]string{
		0:       "0 B",
		500:     "500 B",
		1024:    "1.0 KB",
		1536:    "1.5 KB",
		1048576: "1.0 MB",
	}
	for in, want := range cases {
		if got := humanSize(in); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestInSandbox(t *testing.T) {
	r := &SessionReport{SandboxDir: `C:\VSM\sandbox`}
	if !r.InSandbox(`C:\VSM\sandbox\appdata\f.txt`) {
		t.Error("a path inside the sandbox must be reported as in-sandbox")
	}
	if r.InSandbox(`C:\Users\X\file`) {
		t.Error("a path outside the sandbox must not be reported as in-sandbox")
	}
}

func TestIntendedDestination(t *testing.T) {
	r := &SessionReport{Redirects: []RedirectInfo{{
		EnvVar:  "APPDATA",
		Real:    `C:\Users\X\AppData\Roaming`,
		Virtual: `C:\VSM\sandbox\appdata`,
	}}}
	got := r.IntendedDestination(`C:\VSM\sandbox\appdata\evil.txt`)
	if want := `C:\Users\X\AppData\Roaming\evil.txt`; got != want {
		t.Errorf("IntendedDestination = %q, want %q", got, want)
	}
	if r.IntendedDestination(`C:\elsewhere\x`) != "" {
		t.Error("a non-virtualised path must map to an empty destination")
	}
}

func TestIsExternalIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":     true,
		"1.1.1.1":     true,
		"127.0.0.1":   false,
		"192.168.0.1": false,
		"10.1.2.3":    false,
		"":            false,
		"not-an-ip":   false,
	}
	for ip, want := range cases {
		if got := isExternalIP(ip); got != want {
			t.Errorf("isExternalIP(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestWriteIOCs(t *testing.T) {
	r := &SessionReport{
		Version:     "test",
		SandboxDir:  `C:\sb`,
		GeneratedAt: time.Now(),
		Target:      TargetInfo{Path: `C:\s.exe`, SHA256: "abc123"},
		Analysis:    analyze.Result{Level: "dangerous", Score: 35},
		FSChanges: []snapshot.FSChange{{
			Type:  snapshot.Added,
			Path:  `C:\sb\appdata\drop.exe`,
			After: &snapshot.FileEntry{Path: `C:\sb\appdata\drop.exe`, SHA256: "deadbeef"},
		}},
	}
	path := filepath.Join(t.TempDir(), "iocs.txt")
	if err := r.WriteIOCs(path); err != nil {
		t.Fatalf("WriteIOCs: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read iocs: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, "deadbeef") {
		t.Error("IOC sheet must contain the dropped file's SHA-256")
	}
	if !strings.Contains(s, "## dropped-file") {
		t.Error("IOC sheet must contain a dropped-file section")
	}
}
