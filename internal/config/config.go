// Package config holds the runtime configuration of a sandbox session:
// which directories and registry keys to watch, where to redirect writes,
// and the process containment limits.
//
// Пакет config хранит конфигурацию сессии песочницы: какие каталоги и
// ключи реестра отслеживать, куда перенаправлять запись и какие лимиты
// накладывать на процесс.
package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Redirect describes one virtualised environment variable. The sandboxed
// process sees Virtual, while the report maps it back to Real.
//
// Redirect описывает одну виртуализированную переменную окружения.
// Процесс в песочнице видит Virtual, а отчёт сопоставляет её с Real.
type Redirect struct {
	EnvVar  string // e.g. APPDATA
	Real    string // the genuine system path
	Virtual string // the sandbox path the process actually writes to
}

// JobLimits caps the resources of the contained process tree.
// JobLimits ограничивает ресурсы дерева процессов в песочнице.
type JobLimits struct {
	MaxProcesses int   // 0 = unlimited
	MaxMemoryMB  int64 // 0 = unlimited
}

// Config is the full description of a sandbox run.
// Config — полное описание запуска в песочнице.
type Config struct {
	Lang          string
	WorkspaceDir  string     // base folder for all sessions
	WatchRoots    []string   // directories snapshotted before/after the run
	RegistryRoots []string   // registry keys snapshotted before/after the run
	RegWatchRoots []string   // registry keys watched in real time (autorun)
	Redirects     []Redirect // environment redirections applied to the child
	TimeoutSec    int        // 0 = no timeout
	LowIntegrity  bool       // run the child at Low integrity level
	HashLimitMB   int64      // skip SHA-256 for files larger than this
	Job           JobLimits
}

// DefaultRegistryRoots returns the forensically relevant registry locations
// that are snapshotted by default.
//
// DefaultRegistryRoots возвращает криминалистически значимые ветки реестра,
// которые отслеживаются по умолчанию.
func DefaultRegistryRoots() []string {
	return []string{
		`HKCU\Software`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		`HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows`,
	}
}

// AutorunRegistryRoots returns the narrow, high-signal autostart keys watched
// in real time. They are deliberately specific: watching a broad hive would
// drown the timeline in unrelated background activity.
//
// AutorunRegistryRoots возвращает узкие ключи автозапуска для слежения в
// реальном времени — широкая ветка утопила бы хронологию в фоновом шуме.
func AutorunRegistryRoots() []string {
	return []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		`HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows`,
	}
}

// defaultWatchRoots returns the user/system directories most software touches.
func defaultWatchRoots() []string {
	profile := os.Getenv("USERPROFILE")
	candidates := []string{
		os.Getenv("APPDATA"),
		os.Getenv("LOCALAPPDATA"),
		os.Getenv("ProgramData"),
		os.Getenv("PUBLIC"),
		filepath.Join(profile, "Desktop"),
		filepath.Join(profile, "Documents"),
		filepath.Join(profile, "Downloads"),
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		filepath.Join(os.Getenv("WINDIR"), "Temp"),
	}
	return dedup(candidates)
}

// Default builds a Config with sensible defaults for the given language.
// Default строит Config с разумными настройками по умолчанию.
func Default(lang string) *Config {
	ws := filepath.Join(localAppData(), "VSM", "workspace")
	return &Config{
		Lang:          lang,
		WorkspaceDir:  ws,
		WatchRoots:    defaultWatchRoots(),
		RegistryRoots: DefaultRegistryRoots(),
		RegWatchRoots: AutorunRegistryRoots(),
		TimeoutSec:    120,
		LowIntegrity:  true,
		HashLimitMB:   128,
		Job:           JobLimits{MaxProcesses: 64, MaxMemoryMB: 2048},
	}
}

func localAppData() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return v
	}
	return os.TempDir()
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		c := filepath.Clean(s)
		key := strings.ToLower(c)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}
