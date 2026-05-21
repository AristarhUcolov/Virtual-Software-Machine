package wsb

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateProducesValidXML(t *testing.T) {
	out, err := Generate(Options{
		HostFolder:  `C:\stage`,
		SandboxRoot: `C:\VSM`,
		Command:     `C:\VSM\vsm-cli.exe -target C:\VSM\sample.exe`,
		Networking:  true,
		MemoryMB:    4096,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// The result must parse back as well-formed XML.
	var c wsbConfig
	if err := xml.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("generated .wsb is not valid XML: %v", err)
	}
	if c.Networking != "Default" {
		t.Errorf("Networking = %q, want Default", c.Networking)
	}
	if len(c.MappedFolders.Folders) != 1 {
		t.Fatalf("expected one mapped folder, got %d", len(c.MappedFolders.Folders))
	}
	if c.MappedFolders.Folders[0].HostFolder != `C:\stage` {
		t.Errorf("HostFolder = %q", c.MappedFolders.Folders[0].HostFolder)
	}
	if !strings.Contains(c.LogonCommand.Command, "vsm-cli.exe") {
		t.Errorf("logon command missing the CLI: %q", c.LogonCommand.Command)
	}
}

func TestGenerateNetworkingDisabled(t *testing.T) {
	out, _ := Generate(Options{HostFolder: `C:\s`, SandboxRoot: `C:\VSM`, Networking: false})
	if !strings.Contains(out, "<Networking>Disable</Networking>") {
		t.Error("networking-off config must disable Networking")
	}
}

func TestExePathUnderSystem32(t *testing.T) {
	if !strings.HasSuffix(ExePath(), `System32\WindowsSandbox.exe`) {
		t.Errorf("ExePath = %q, want it to end in System32\\WindowsSandbox.exe", ExePath())
	}
}

func TestPrepareStagesEverything(t *testing.T) {
	sample := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(sample, []byte("MZ fake sample"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()

	wsbPath, reportDir, err := Prepare(sample, "ru", base)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, err := os.Stat(wsbPath); err != nil {
		t.Errorf(".wsb file was not written: %v", err)
	}
	if _, err := os.Stat(reportDir); err != nil {
		t.Errorf("report directory was not created: %v", err)
	}

	staging := filepath.Dir(wsbPath)
	if _, err := os.Stat(filepath.Join(staging, "vsm-cli.exe")); err != nil {
		t.Error("the VSM CLI was not staged into the sandbox folder")
	}
	if _, err := os.Stat(filepath.Join(staging, "sample.exe")); err != nil {
		t.Error("the sample was not staged into the sandbox folder")
	}

	data, err := os.ReadFile(wsbPath)
	if err != nil {
		t.Fatal(err)
	}
	var c wsbConfig
	if err := xml.Unmarshal(data, &c); err != nil {
		t.Fatalf("staged .wsb is not valid XML: %v", err)
	}
	if !strings.Contains(c.LogonCommand.Command, "sample.exe") {
		t.Errorf("logon command must reference the sample: %q", c.LogonCommand.Command)
	}
	if len(c.MappedFolders.Folders) != 1 || c.MappedFolders.Folders[0].HostFolder != staging {
		t.Errorf("the staging folder must be mapped into the sandbox")
	}
}
