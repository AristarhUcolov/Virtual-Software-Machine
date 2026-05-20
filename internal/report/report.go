// Package report turns the result of a sandbox session into a structured
// JSON document and a human-readable bilingual HTML forensic report.
//
// Пакет report превращает результат сессии песочницы в структурированный
// JSON-документ и удобный двуязычный HTML-отчёт для криминалистики.
package report

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"vsm/internal/analyze"
	"vsm/internal/monitor"
	"vsm/internal/netmon"
	"vsm/internal/procmon"
	"vsm/internal/snapshot"
)

// TargetInfo fingerprints the analysed file. // TargetInfo — отпечаток файла.
type TargetInfo struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ProcessInfo describes the contained process. // ProcessInfo — данные процесса.
type ProcessInfo struct {
	PID           int       `json:"pid"`
	ExitCode      uint32    `json:"exit_code"`
	IntegrityMode string    `json:"integrity_mode"` // "low" or "medium"
	Started       time.Time `json:"started"`
	Ended         time.Time `json:"ended"`
	TimedOut      bool      `json:"timed_out"`
}

// Duration returns how long the process ran. // Duration — время работы процесса.
func (p ProcessInfo) Duration() time.Duration { return p.Ended.Sub(p.Started) }

// RedirectInfo records one virtualised path mapping. // RedirectInfo — одно перенаправление.
type RedirectInfo struct {
	EnvVar  string `json:"env_var"`
	Real    string `json:"real"`
	Virtual string `json:"virtual"`
}

// SessionReport is the complete result of one sandbox run.
// SessionReport — полный результат одного запуска в песочнице.
type SessionReport struct {
	Tool        string               `json:"tool"`
	Version     string               `json:"version"`
	Lang        string               `json:"lang"`
	GeneratedAt time.Time            `json:"generated_at"`
	SessionDir  string               `json:"session_dir"`
	SandboxDir  string               `json:"sandbox_dir"`
	Target      TargetInfo           `json:"target"`
	Process     ProcessInfo          `json:"process"`
	Redirects   []RedirectInfo       `json:"redirects"`
	FSChanges   []snapshot.FSChange  `json:"fs_changes"`
	RegChanges  []snapshot.RegChange `json:"reg_changes"`
	Timeline    []monitor.Event      `json:"timeline"`
	Network     []netmon.Conn        `json:"network"`
	Processes   []procmon.Process    `json:"processes"`
	Analysis    analyze.Result       `json:"analysis"`
}

// IntendedDestination maps a path that lives inside a sandbox redirect back to
// the real location the program believed it was writing to. It returns an
// empty string when the path is not virtualised.
//
// IntendedDestination сопоставляет путь внутри перенаправления песочницы с
// реальным расположением, куда программа «думала», что пишет. Возвращает
// пустую строку, если путь не виртуализирован.
func (r *SessionReport) IntendedDestination(path string) string {
	lp := strings.ToLower(path)
	for _, rd := range r.Redirects {
		v := strings.ToLower(rd.Virtual)
		if v != "" && strings.HasPrefix(lp, v) {
			return rd.Real + path[len(rd.Virtual):]
		}
	}
	return ""
}

// InSandbox reports whether path lies inside the sandbox directory — i.e. it
// is a write the analysed program itself made (its own footprint), rather than
// unrelated OS background activity captured by the snapshot diff.
//
// InSandbox сообщает, находится ли путь внутри каталога песочницы — то есть
// это запись, сделанная самой анализируемой программой (её след), а не
// посторонняя фоновая активность ОС, попавшая в снимок.
func (r *SessionReport) InSandbox(path string) bool {
	if r.SandboxDir == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(path), strings.ToLower(r.SandboxDir))
}

// WriteJSON serialises the report to path as indented JSON.
// WriteJSON сериализует отчёт в path как форматированный JSON.
func (r *SessionReport) WriteJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
