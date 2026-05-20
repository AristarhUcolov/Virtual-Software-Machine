// Package sandbox orchestrates a full analysis session: it snapshots the
// system, launches the target inside a user-mode container with redirected
// storage, watches activity, and produces a forensic report.
//
// Пакет sandbox управляет полной сессией анализа: делает снимок системы,
// запускает цель в user-mode контейнере с перенаправленным хранилищем,
// наблюдает за активностью и формирует криминалистический отчёт.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vsm/internal/analyze"
	"vsm/internal/config"
	"vsm/internal/i18n"
	"vsm/internal/monitor"
	"vsm/internal/netmon"
	"vsm/internal/procmon"
	"vsm/internal/regmon"
	"vsm/internal/report"
	"vsm/internal/snapshot"
)

// Version is the tool version embedded into every report.
// Version — версия инструмента, попадающая в каждый отчёт.
const Version = "0.1.0"

// Options describes a single run requested by the user.
// Options описывает один запуск, запрошенный пользователем.
type Options struct {
	TargetPath string
	Args       []string
}

// Result bundles the report with the on-disk locations of its files.
// Result объединяет отчёт с путями к его файлам на диске.
type Result struct {
	Report     *report.SessionReport
	HTMLPath   string
	JSONPath   string
	SessionDir string
}

// logf is a no-op-safe progress sink. // logf — безопасный приёмник прогресса.
type logf func(string)

func (l logf) say(s string) {
	if l != nil {
		l(s)
	}
}

// Run executes the whole analysis session and returns its Result.
// Run выполняет всю сессию анализа и возвращает Result.
func Run(cfg *config.Config, opts Options, log logf) (*Result, error) {
	info, err := os.Stat(opts.TargetPath)
	if err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	if info.IsDir() {
		return nil, errors.New("target is a directory, not a file")
	}

	// 1. Session folder. // 1. Папка сессии.
	stamp := time.Now().Format("20060102-150405")
	sessionDir := filepath.Join(cfg.WorkspaceDir, "session-"+stamp)
	sandboxRoot := filepath.Join(sessionDir, "sandbox")
	if err := os.MkdirAll(sandboxRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create session dir: %w", err)
	}
	log.say("session: " + sessionDir)

	// 2. Redirected storage. // 2. Перенаправленное хранилище.
	redirects := buildRedirects(sandboxRoot)
	for _, rd := range redirects {
		if err := os.MkdirAll(rd.Virtual, 0o755); err != nil {
			return nil, fmt.Errorf("create redirect dir: %w", err)
		}
	}
	lowerIntegrityOfDir(sandboxRoot, log) // best effort, so a Low-IL child can write

	// 3. Pre-run snapshots. // 3. Снимки до запуска.
	watchRoots := append(append([]string{}, cfg.WatchRoots...), sandboxRoot)
	log.say("status:snapbe")
	fsBefore := snapshot.ScanFS(watchRoots)
	regBefore := snapshot.ScanRegistry(cfg.RegistryRoots)
	log.say(fmt.Sprintf("pre-run: %d files, %d registry keys", len(fsBefore.Files), len(regBefore.Keys)))

	// 4. Real-time watcher — pointed at the sandbox tree only (the broad
	// system roots are covered by the snapshot diff).
	// 4. Наблюдатель в реальном времени — только за деревом песочницы.
	watcher, werr := monitor.Start([]string{sandboxRoot})
	if werr != nil {
		log.say("watcher unavailable: " + werr.Error())
	}

	// Real-time registry watcher over the autostart keys.
	// Слежение за ключами автозапуска в реальном времени.
	regWatcher, rerr := regmon.Start(cfg.RegWatchRoots)
	if rerr != nil {
		log.say("registry watcher unavailable: " + rerr.Error())
	}

	// 5. Launch the contained process. // 5. Запуск процесса в изоляции.
	log.say("status:launch")
	env := buildEnv(redirects)
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	proc, lerr := startSandboxed(opts.TargetPath, opts.Args,
		filepath.Dir(opts.TargetPath), env, cfg.Job, cfg.LowIntegrity, log)
	if lerr != nil {
		if watcher != nil {
			watcher.Stop()
		}
		return nil, fmt.Errorf("launch: %w", lerr)
	}

	// Network monitor — samples the TCP/UDP tables of the job process tree
	// while it runs. // Сетевой монитор — опрашивает TCP/UDP-таблицы дерева job.
	netMon := netmon.Start(proc.Job(), proc.PID(), 350*time.Millisecond)

	// Process monitor — records every process spawned inside the job tree.
	// Монитор процессов — фиксирует каждый процесс дерева job.
	procMon := procmon.Start(proc.Job(), proc.PID(), 250*time.Millisecond)

	res := proc.wait(timeout, log)

	var timeline []monitor.Event
	if watcher != nil {
		timeline = watcher.Stop()
	}
	if regWatcher != nil {
		timeline = append(timeline, regWatcher.Stop()...)
	}
	sort.SliceStable(timeline, func(i, j int) bool {
		return timeline[i].Time.Before(timeline[j].Time)
	})
	netConns := netMon.Stop()
	processes := procMon.Stop()
	proc.close()
	log.say(fmt.Sprintf("process exited: pid=%d code=%d mode=%s", res.PID, res.ExitCode, res.IntegrityMode))

	// 6. Post-run snapshots and diff. // 6. Снимки после запуска и сравнение.
	log.say("status:snapaf")
	fsAfter := snapshot.ScanFS(watchRoots)
	regAfter := snapshot.ScanRegistry(cfg.RegistryRoots)
	log.say("status:diff")
	fsChanges := snapshot.DiffFS(fsBefore, fsAfter, cfg.HashLimitMB*1024*1024)
	regChanges := snapshot.DiffRegistry(regBefore, regAfter)

	// 7. Heuristic verdict + report. // 7. Эвристический вердикт и отчёт.
	log.say("status:report")
	analysis := analyze.Analyze(analyze.Input{
		FS:         fsChanges,
		Reg:        regChanges,
		Net:        netConns,
		Procs:      processes,
		SandboxDir: sandboxRoot,
		TimedOut:   res.TimedOut,
	}, i18n.Normalize(cfg.Lang))
	rep := &report.SessionReport{
		Tool:        "Virtual Software Machine",
		Version:     Version,
		Lang:        cfg.Lang,
		GeneratedAt: time.Now(),
		SessionDir:  sessionDir,
		SandboxDir:  sandboxRoot,
		Target: report.TargetInfo{
			Path:   opts.TargetPath,
			SHA256: snapshot.HashFile(opts.TargetPath),
			Size:   info.Size(),
		},
		Process: report.ProcessInfo{
			PID:           res.PID,
			ExitCode:      res.ExitCode,
			IntegrityMode: res.IntegrityMode,
			Started:       res.Started,
			Ended:         res.Ended,
			TimedOut:      res.TimedOut,
		},
		Redirects:  redirects,
		FSChanges:  fsChanges,
		RegChanges: regChanges,
		Timeline:   timeline,
		Network:    netConns,
		Processes:  processes,
		Analysis:   analysis,
	}

	out := &Result{
		Report:     rep,
		SessionDir: sessionDir,
		HTMLPath:   filepath.Join(sessionDir, "report.html"),
		JSONPath:   filepath.Join(sessionDir, "report.json"),
	}
	if err := rep.WriteJSON(out.JSONPath); err != nil {
		return out, fmt.Errorf("write json: %w", err)
	}
	if err := rep.WriteHTML(out.HTMLPath); err != nil {
		return out, fmt.Errorf("write html: %w", err)
	}
	log.say("status:done")
	return out, nil
}

// buildRedirects maps virtualised environment variables to sandbox folders.
func buildRedirects(sandboxRoot string) []report.RedirectInfo {
	type spec struct{ env, sub string }
	specs := []spec{
		{"TEMP", "temp"},
		{"TMP", "temp"},
		{"APPDATA", "appdata"},
		{"LOCALAPPDATA", "localappdata"},
	}
	var out []report.RedirectInfo
	for _, s := range specs {
		out = append(out, report.RedirectInfo{
			EnvVar:  s.env,
			Real:    os.Getenv(s.env),
			Virtual: filepath.Join(sandboxRoot, s.sub),
		})
	}
	return out
}

// buildEnv clones the current environment and applies the redirections.
func buildEnv(redirects []report.RedirectInfo) []string {
	env := os.Environ()
	for _, rd := range redirects {
		env = setEnv(env, rd.EnvVar, rd.Virtual)
	}
	return env
}

// setEnv returns env with key set to val (case-insensitive replace).
func setEnv(env []string, key, val string) []string {
	out := make([]string, 0, len(env)+1)
	found := false
	for _, e := range env {
		if eq := strings.IndexByte(e, '='); eq > 0 && strings.EqualFold(e[:eq], key) {
			out = append(out, key+"="+val)
			found = true
		} else {
			out = append(out, e)
		}
	}
	if !found {
		out = append(out, key+"="+val)
	}
	return out
}

// lowerIntegrityOfDir marks dir as Low integrity so a Low-IL child can write
// into it. Failures are non-fatal: the medium-integrity fallback still works.
func lowerIntegrityOfDir(dir string, log logf) {
	cmd := exec.Command("icacls", dir, "/setintegritylevel", "(OI)(CI)Low")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.say("icacls integrity label skipped: " + strings.TrimSpace(string(out)))
	}
}
