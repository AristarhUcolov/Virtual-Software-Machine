// Package wsb integrates VSM with Windows Sandbox — the built-in, disposable,
// hardware-isolated (Hyper-V) lightweight VM. It stages the VSM CLI together
// with the sample, generates a .wsb configuration that runs the analysis
// inside the sandbox, and returns the report through a mapped folder.
//
// Running the analysis inside Windows Sandbox gives genuine hardware
// isolation, and — because the disposable VM has no background software —
// a snapshot diff that is naturally free of OS noise.
//
// Пакет wsb интегрирует VSM с Windows Sandbox — встроенной одноразовой
// аппаратно-изолированной (Hyper-V) лёгкой ВМ. Он собирает staging-папку с
// VSM CLI и образцом, генерирует конфиг .wsb, который запускает анализ внутри
// песочницы, и возвращает отчёт через подключённую папку.
package wsb

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// mountPoint is where the staging folder appears inside the sandbox.
const mountPoint = `C:\VSM`

// Options configures a generated .wsb file.
// Options настраивает генерируемый файл .wsb.
type Options struct {
	HostFolder  string // folder on the host mapped into the sandbox
	SandboxRoot string // mount point inside the sandbox
	Command     string // logon command executed inside the sandbox
	Networking  bool   // whether the sandbox has network access
	MemoryMB    int    // sandbox RAM (Windows Sandbox minimum is 2048)
}

// wsbConfig mirrors the Windows Sandbox .wsb XML schema.
type wsbConfig struct {
	XMLName       xml.Name `xml:"Configuration"`
	Networking    string   `xml:"Networking"`
	MemoryInMB    int      `xml:"MemoryInMB,omitempty"`
	MappedFolders struct {
		Folders []mappedFolder `xml:"MappedFolder"`
	} `xml:"MappedFolders"`
	LogonCommand struct {
		Command string `xml:"Command"`
	} `xml:"LogonCommand"`
}

type mappedFolder struct {
	HostFolder    string `xml:"HostFolder"`
	SandboxFolder string `xml:"SandboxFolder"`
	ReadOnly      bool   `xml:"ReadOnly"`
}

// Generate renders a Windows Sandbox .wsb configuration file.
// Generate формирует конфигурационный файл .wsb для Windows Sandbox.
func Generate(o Options) (string, error) {
	var c wsbConfig
	if o.Networking {
		c.Networking = "Default"
	} else {
		c.Networking = "Disable"
	}
	c.MemoryInMB = o.MemoryMB
	c.MappedFolders.Folders = []mappedFolder{{
		HostFolder:    o.HostFolder,
		SandboxFolder: o.SandboxRoot,
		ReadOnly:      false,
	}}
	c.LogonCommand.Command = o.Command

	body, err := xml.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	return xml.Header + string(body) + "\n", nil
}

// ExePath returns the expected location of WindowsSandbox.exe.
// ExePath возвращает ожидаемое расположение WindowsSandbox.exe.
func ExePath() string {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = `C:\Windows`
	}
	return filepath.Join(windir, "System32", "WindowsSandbox.exe")
}

// Available reports whether Windows Sandbox is installed on this machine.
// Available сообщает, установлен ли Windows Sandbox на этой машине.
func Available() bool {
	_, err := os.Stat(ExePath())
	return err == nil
}

// Prepare builds a staging folder (VSM CLI + sample), writes a .wsb config
// that runs the analysis inside Windows Sandbox, and returns the path to the
// .wsb file and the host folder where the report will appear.
//
// Prepare собирает staging-папку (VSM CLI + образец), пишет конфиг .wsb,
// запускающий анализ внутри Windows Sandbox, и возвращает путь к файлу .wsb
// и папку на хосте, куда попадёт отчёт.
func Prepare(targetPath, lang, workspaceBase string) (wsbPath, reportDir string, err error) {
	cliPath, err := os.Executable()
	if err != nil {
		return "", "", fmt.Errorf("locate VSM CLI: %w", err)
	}
	stamp := time.Now().Format("20060102-150405")
	staging := filepath.Join(workspaceBase, "wsb-"+stamp)
	reportDir = filepath.Join(staging, "report")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", "", fmt.Errorf("create staging dir: %w", err)
	}

	if err := copyFile(cliPath, filepath.Join(staging, "vsm-cli.exe")); err != nil {
		return "", "", fmt.Errorf("stage VSM CLI: %w", err)
	}
	sample := filepath.Base(targetPath)
	if err := copyFile(targetPath, filepath.Join(staging, sample)); err != nil {
		return "", "", fmt.Errorf("stage sample: %w", err)
	}

	// Command executed at sandbox logon. Paths are quoted to tolerate spaces.
	cmd := fmt.Sprintf(`"%s\vsm-cli.exe" -target "%s\%s" -out "%s\report" -lang %s`,
		mountPoint, mountPoint, sample, mountPoint, lang)

	xmlText, err := Generate(Options{
		HostFolder:  staging,
		SandboxRoot: mountPoint,
		Command:     cmd,
		Networking:  true,
		MemoryMB:    4096,
	})
	if err != nil {
		return "", "", err
	}
	wsbPath = filepath.Join(staging, "analysis.wsb")
	if err := os.WriteFile(wsbPath, []byte(xmlText), 0o644); err != nil {
		return "", "", fmt.Errorf("write .wsb: %w", err)
	}
	return wsbPath, reportDir, nil
}

// copyFile copies src to dst, preserving nothing but the bytes.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
