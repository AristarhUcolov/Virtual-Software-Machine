package analyze

import (
	"testing"

	"vsm/internal/i18n"
	"vsm/internal/netmon"
	"vsm/internal/procmon"
	"vsm/internal/snapshot"
)

// hasSeverity reports whether the result contains an indicator of severity s.
func hasSeverity(r Result, s Severity) bool {
	for _, ind := range r.Indicators {
		if ind.Severity == s {
			return true
		}
	}
	return false
}

func TestAnalyzeCleanOnEmptyInput(t *testing.T) {
	r := Analyze(Input{}, i18n.EN)
	if r.Level != "clean" {
		t.Errorf("level = %q, want clean", r.Level)
	}
	if r.Score != 0 {
		t.Errorf("score = %d, want 0", r.Score)
	}
	if len(r.Indicators) != 0 {
		t.Errorf("indicators = %d, want 0", len(r.Indicators))
	}
}

func TestAnalyzeRegistryAutorunIsDangerous(t *testing.T) {
	in := Input{Reg: []snapshot.RegChange{{
		Type:      snapshot.Added,
		KeyPath:   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		ValueName: "Evil",
	}}}
	r := Analyze(in, i18n.EN)
	if r.Level != "dangerous" {
		t.Errorf("level = %q, want dangerous", r.Level)
	}
	if !hasSeverity(r, High) {
		t.Error("expected a High-severity indicator for an autorun write")
	}
}

func TestAnalyzeExternalNetworkIsSuspicious(t *testing.T) {
	in := Input{Net: []netmon.Conn{{
		Proto: "TCP", RemoteAddr: "8.8.8.8", RemotePort: 443, State: "ESTABLISHED",
	}}}
	r := Analyze(in, i18n.EN)
	if r.Level != "suspicious" {
		t.Errorf("level = %q, want suspicious", r.Level)
	}
}

func TestAnalyzeLoopbackIsNotFlagged(t *testing.T) {
	in := Input{Net: []netmon.Conn{{
		Proto: "TCP", RemoteAddr: "127.0.0.1", RemotePort: 50000, State: "ESTABLISHED",
	}}}
	if r := Analyze(in, i18n.EN); r.Level != "clean" {
		t.Errorf("loopback connection: level = %q, want clean", r.Level)
	}
}

func TestAnalyzeDroppedExeInSandboxIsHigh(t *testing.T) {
	sb := `C:\sandbox`
	in := Input{
		SandboxDir: sb,
		FS: []snapshot.FSChange{{
			Type:  snapshot.Added,
			Path:  sb + `\appdata\dropper.exe`,
			After: &snapshot.FileEntry{Path: sb + `\appdata\dropper.exe`},
		}},
	}
	if r := Analyze(in, i18n.EN); !hasSeverity(r, High) {
		t.Error("an executable dropped inside the sandbox must be High severity")
	}
}

func TestAnalyzeSuspiciousCommandLine(t *testing.T) {
	in := Input{Procs: []procmon.Process{
		{PID: 1, Image: `C:\sample.exe`, IsRoot: true},
		{PID: 2, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			CommandLine: `powershell -NoProfile -EncodedCommand SQBFAFgA`},
	}}
	if r := Analyze(in, i18n.EN); !hasSeverity(r, High) {
		t.Error("an encoded PowerShell command line must be High severity")
	}
}

func TestAnalyzeLolbinChildIsHigh(t *testing.T) {
	in := Input{Procs: []procmon.Process{
		{PID: 1, Image: `C:\sample.exe`, IsRoot: true},
		{PID: 2, Image: `C:\Windows\System32\rundll32.exe`},
	}}
	if r := Analyze(in, i18n.EN); !hasSeverity(r, High) {
		t.Error("a rundll32 child process must be High severity")
	}
}

func TestAnalyzeTimeoutIsInfoOnly(t *testing.T) {
	r := Analyze(Input{TimedOut: true}, i18n.EN)
	if r.Level != "clean" {
		t.Errorf("timeout-only run: level = %q, want clean", r.Level)
	}
	if len(r.Indicators) != 1 || r.Indicators[0].Severity != Info {
		t.Errorf("expected exactly one Info indicator, got %+v", r.Indicators)
	}
}
