// Package analyze turns the raw observations of a sandbox session into a
// concise, prioritised verdict: it applies forensic heuristics to the file,
// registry, network and process data and reports the indicators of
// compromise (IOC) an analyst should look at first.
//
// Пакет analyze превращает сырые наблюдения сессии песочницы в краткий
// приоритизированный вердикт: применяет криминалистические эвристики к
// данным о файлах, реестре, сети и процессах и сообщает индикаторы
// компрометации (IOC), на которые аналитику стоит смотреть в первую очередь.
package analyze

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"vsm/internal/i18n"
	"vsm/internal/netmon"
	"vsm/internal/procmon"
	"vsm/internal/snapshot"
)

// Severity ranks how much attention an indicator deserves.
// Severity — насколько индикатор требует внимания.
type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
	Info   Severity = "info"
)

// Indicator is one finding of the heuristic analysis.
// Indicator — одна находка эвристического анализа.
type Indicator struct {
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
}

// Result is the overall verdict plus the ordered list of indicators.
// Result — итоговый вердикт и упорядоченный список индикаторов.
type Result struct {
	Level      string      `json:"level"`       // clean / suspicious / dangerous
	LevelText  string      `json:"level_text"`  // localized verdict sentence
	Score      int         `json:"score"`       // 0..100 risk score
	Indicators []Indicator `json:"indicators"`
}

// Input bundles the raw session data passed to the analyzer.
// Input объединяет сырые данные сессии для анализатора.
type Input struct {
	FS         []snapshot.FSChange
	Reg        []snapshot.RegChange
	Net        []netmon.Conn
	Procs      []procmon.Process
	SandboxDir string // writes under this path are the program's own footprint
	TargetPath string // the analysed file itself
	TimedOut   bool
}

// executable file extensions that are notable when freshly created.
var execExt = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".scr": true, ".com": true,
	".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".vbe": true,
	".js": true, ".jse": true, ".wsf": true, ".hta": true, ".jar": true,
	".msi": true, ".cpl": true, ".lnk": true,
}

// living-off-the-land binaries frequently abused by malware.
var lolbins = map[string]bool{
	"powershell.exe": true, "powershell_ise.exe": true, "wscript.exe": true,
	"cscript.exe": true, "rundll32.exe": true, "regsvr32.exe": true,
	"mshta.exe": true, "bitsadmin.exe": true, "certutil.exe": true,
	"schtasks.exe": true, "wmic.exe": true, "installutil.exe": true,
	"msbuild.exe": true, "regasm.exe": true, "regsvcs.exe": true,
	"cmd.exe": true,
}

// Analyze applies every heuristic and returns the verdict in the given language.
// Analyze применяет все эвристики и возвращает вердикт на указанном языке.
func Analyze(in Input, lang i18n.Lang) Result {
	var inds []Indicator

	inds = appendIf(inds, registryAutorun(in.Reg, lang))
	inds = appendIf(inds, startupFolder(in.FS, lang))
	inds = appendIf(inds, droppedExecutables(in.FS, in.SandboxDir, lang))
	inds = appendIf(inds, systemDirChanges(in.FS, lang))
	inds = appendIf(inds, externalNetwork(in.Net, lang))
	inds = appendIf(inds, lolbinChildren(in.Procs, lang))
	inds = appendIf(inds, suspiciousCommandLine(in.Procs, lang))
	inds = appendIf(inds, hostsFileModified(in.FS, lang))
	inds = appendIf(inds, scheduledTaskCreated(in.FS, lang))
	inds = appendIf(inds, policyTampering(in.Reg, lang))
	inds = appendIf(inds, processFromDroppedFile(in.FS, in.Procs, lang))
	inds = appendIf(inds, selfDeletion(in.FS, in.TargetPath, lang))
	inds = appendIf(inds, ransomwarePattern(in.FS, lang))
	inds = appendIf(inds, spawnedChildren(in.Procs, lang))
	if in.TimedOut {
		inds = append(inds, Indicator{
			Severity: Info,
			Title:    i18n.T(lang, "ioc.timeout"),
			Detail:   i18n.T(lang, "ioc.timeout.detail"),
		})
	}

	sort.SliceStable(inds, func(i, j int) bool {
		return sevRank(inds[i].Severity) < sevRank(inds[j].Severity)
	})

	var hi, med, low int
	for _, ind := range inds {
		switch ind.Severity {
		case High:
			hi++
		case Medium:
			med++
		case Low:
			low++
		}
	}
	score := hi*35 + med*12 + low*4
	if score > 100 {
		score = 100
	}
	level := "clean"
	switch {
	case hi > 0:
		level = "dangerous"
	case med > 0:
		level = "suspicious"
	}
	return Result{
		Level:      level,
		LevelText:  i18n.T(lang, "verdict."+level),
		Score:      score,
		Indicators: inds,
	}
}

// registryAutorun flags registry writes into autostart locations.
func registryAutorun(reg []snapshot.RegChange, lang i18n.Lang) *Indicator {
	var hits []string
	for _, c := range reg {
		if c.Type == snapshot.Deleted {
			continue
		}
		k := strings.ToLower(c.KeyPath)
		if strings.Contains(k, `currentversion\run`) || strings.Contains(k, "winlogon") {
			hits = append(hits, c.KeyPath+` \ `+c.ValueName)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{
		Severity: High,
		Title:    i18n.T(lang, "ioc.run"),
		Detail:   joinSample(hits, 6),
	}
}

// startupFolder flags new files placed in a Startup directory.
func startupFolder(fs []snapshot.FSChange, lang i18n.Lang) *Indicator {
	var hits []string
	for _, c := range fs {
		if c.Type == snapshot.Deleted {
			continue
		}
		if strings.Contains(strings.ToLower(c.Path), `\start menu\programs\startup`) {
			hits = append(hits, c.Path)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{
		Severity: High,
		Title:    i18n.T(lang, "ioc.startup"),
		Detail:   joinSample(hits, 6),
	}
}

// droppedExecutables flags freshly created executable / script files. A drop
// inside the sandbox is, by construction, the analysed program's own write —
// so it is treated as a high-confidence indicator.
func droppedExecutables(fs []snapshot.FSChange, sandboxDir string, lang i18n.Lang) *Indicator {
	var hits []string
	severity := Medium
	for _, c := range fs {
		if c.Type != snapshot.Added {
			continue
		}
		if !execExt[strings.ToLower(filepath.Ext(c.Path))] {
			continue
		}
		hits = append(hits, c.Path)
		if isSystemDir(c.Path) || isStartup(c.Path) || underDir(c.Path, sandboxDir) {
			severity = High
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{
		Severity: severity,
		Title:    fmt.Sprintf("%s (%d)", i18n.T(lang, "ioc.dropped"), len(hits)),
		Detail:   joinSample(hits, 8),
	}
}

// systemDirChanges flags modifications inside Windows / Program Files.
func systemDirChanges(fs []snapshot.FSChange, lang i18n.Lang) *Indicator {
	var hits []string
	for _, c := range fs {
		if c.Type == snapshot.Deleted {
			continue
		}
		if isSystemDir(c.Path) {
			hits = append(hits, c.Path)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{
		Severity: Medium,
		Title:    fmt.Sprintf("%s (%d)", i18n.T(lang, "ioc.sysdir"), len(hits)),
		Detail:   joinSample(hits, 6),
	}
}

// externalNetwork flags connections to non-local, non-private addresses.
func externalNetwork(net []netmon.Conn, lang i18n.Lang) *Indicator {
	var hits []string
	for _, c := range net {
		if !isExternal(c.RemoteAddr) {
			continue
		}
		line := fmt.Sprintf("%s %s:%d", c.Proto, c.RemoteAddr, c.RemotePort)
		if c.Service != "" {
			line += " " + c.Service
		}
		if c.Host != "" {
			line += " (" + strings.TrimRight(c.Host, ".") + ")"
		}
		hits = append(hits, line)
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{
		Severity: Medium,
		Title:    fmt.Sprintf("%s (%d)", i18n.T(lang, "ioc.network"), len(hits)),
		Detail:   joinSample(hits, 10),
	}
}

// lolbinChildren flags spawned child processes that are known LOLBins.
func lolbinChildren(procs []procmon.Process, lang i18n.Lang) *Indicator {
	var hits []string
	for _, p := range procs {
		if p.IsRoot || p.Image == "" {
			continue
		}
		base := strings.ToLower(filepath.Base(p.Image))
		if lolbins[base] {
			hits = append(hits, p.Image)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{
		Severity: High,
		Title:    i18n.T(lang, "ioc.lolbin"),
		Detail:   joinSample(hits, 8),
	}
}

// command-line fragments characteristic of malicious / obfuscated execution.
var suspiciousCmdTokens = []string{
	"-enc ", "-encodedcommand", "frombase64string", "downloadstring",
	"downloadfile", "invoke-expression", "invoke-webrequest", "iex(", "iex ",
	"-w hidden", "-windowstyle hidden", "-urlcache", "/i:http",
	"mshta http", "mshta javascript", "mshta vbscript", "-decode",
}

// suspiciousCommandLine flags processes started with an obfuscated or
// download-and-execute style command line.
func suspiciousCommandLine(procs []procmon.Process, lang i18n.Lang) *Indicator {
	var hits []string
	for _, p := range procs {
		cl := strings.ToLower(p.CommandLine)
		if cl == "" {
			continue
		}
		for _, tok := range suspiciousCmdTokens {
			if strings.Contains(cl, tok) {
				hits = append(hits, p.CommandLine)
				break
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{
		Severity: High,
		Title:    i18n.T(lang, "ioc.cmdline"),
		Detail:   joinSample(hits, 6),
	}
}

// hostsFileModified flags any edit to the Windows hosts file, a classic
// DNS-hijacking technique.
func hostsFileModified(fs []snapshot.FSChange, lang i18n.Lang) *Indicator {
	for _, c := range fs {
		if c.Type == snapshot.Deleted {
			continue
		}
		if strings.Contains(strings.ToLower(c.Path), `\drivers\etc\hosts`) {
			return &Indicator{Severity: High, Title: i18n.T(lang, "ioc.hosts"), Detail: c.Path}
		}
	}
	return nil
}

// scheduledTaskCreated flags new files dropped into a Task Scheduler folder —
// persistence via a scheduled task.
func scheduledTaskCreated(fs []snapshot.FSChange, lang i18n.Lang) *Indicator {
	var hits []string
	for _, c := range fs {
		if c.Type != snapshot.Added {
			continue
		}
		lp := strings.ToLower(c.Path)
		if strings.Contains(lp, `\system32\tasks\`) || strings.Contains(lp, `\windows\tasks\`) {
			hits = append(hits, c.Path)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{Severity: High, Title: i18n.T(lang, "ioc.schtask"), Detail: joinSample(hits, 6)}
}

// policyTampering flags registry writes that disable system tools — Task
// Manager, the registry editor, Run, the control panel, etc.
func policyTampering(reg []snapshot.RegChange, lang i18n.Lang) *Indicator {
	var hits []string
	for _, c := range reg {
		if c.Type == snapshot.Deleted {
			continue
		}
		k := strings.ToLower(c.KeyPath)
		if strings.Contains(k, `\policies\system`) || strings.Contains(k, `\policies\explorer`) {
			hits = append(hits, c.KeyPath+`\`+c.ValueName)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{Severity: High, Title: i18n.T(lang, "ioc.policy"), Detail: joinSample(hits, 6)}
}

// processFromDroppedFile flags a process whose image is a file the analysed
// program created during the run — the defining behaviour of a dropper.
func processFromDroppedFile(fs []snapshot.FSChange, procs []procmon.Process, lang i18n.Lang) *Indicator {
	dropped := map[string]bool{}
	for _, c := range fs {
		if c.Type == snapshot.Added {
			dropped[strings.ToLower(c.Path)] = true
		}
	}
	var hits []string
	for _, p := range procs {
		if p.Image != "" && dropped[strings.ToLower(p.Image)] {
			hits = append(hits, p.Image)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{Severity: High, Title: i18n.T(lang, "ioc.dropexec"), Detail: joinSample(hits, 6)}
}

// selfDeletion flags the analysed file deleting itself — a common
// anti-forensics move.
func selfDeletion(fs []snapshot.FSChange, targetPath string, lang i18n.Lang) *Indicator {
	if targetPath == "" {
		return nil
	}
	tp := strings.ToLower(targetPath)
	for _, c := range fs {
		if c.Type == snapshot.Deleted && strings.ToLower(c.Path) == tp {
			return &Indicator{Severity: High, Title: i18n.T(lang, "ioc.selfdel"), Detail: c.Path}
		}
	}
	return nil
}

// ransomNoteTokens are file-name fragments typical of ransom notes.
var ransomNoteTokens = []string{
	"decrypt", "_readme", "ransom", "your-files", "your_files",
	"howto_restore", "how_to_decrypt", "restore-my-files", "recover-files",
	"recovery_instructions", "readme_to_recover", "restore_files",
}

// ransomwareMassModified is the number of modified files above which the run
// looks like bulk encryption rather than ordinary activity.
const ransomwareMassModified = 200

// ransomwarePattern flags ransomware-like behaviour: bulk file modification
// (mass encryption) and the appearance of ransom-note files.
func ransomwarePattern(fs []snapshot.FSChange, lang i18n.Lang) *Indicator {
	var notes []string
	modified := 0
	for _, c := range fs {
		if c.Type == snapshot.Modified {
			modified++
		}
		if c.Type == snapshot.Added {
			base := strings.ToLower(filepath.Base(c.Path))
			for _, tok := range ransomNoteTokens {
				if strings.Contains(base, tok) {
					notes = append(notes, c.Path)
					break
				}
			}
		}
	}
	if len(notes) == 0 && modified < ransomwareMassModified {
		return nil
	}
	var detail string
	if modified >= ransomwareMassModified {
		detail = fmt.Sprintf("mass file modification: %d", modified)
	}
	if len(notes) > 0 {
		if detail != "" {
			detail += "\n"
		}
		detail += joinSample(notes, 6)
	}
	return &Indicator{Severity: High, Title: i18n.T(lang, "ioc.ransomware"), Detail: detail}
}

// spawnedChildren reports non-trivial child processes (excluding conhost).
func spawnedChildren(procs []procmon.Process, lang i18n.Lang) *Indicator {
	var hits []string
	for _, p := range procs {
		if p.IsRoot || p.Image == "" {
			continue
		}
		if strings.EqualFold(filepath.Base(p.Image), "conhost.exe") {
			continue
		}
		hits = append(hits, p.Image)
	}
	if len(hits) == 0 {
		return nil
	}
	return &Indicator{
		Severity: Info,
		Title:    fmt.Sprintf("%s (%d)", i18n.T(lang, "ioc.children"), len(hits)),
		Detail:   joinSample(hits, 8),
	}
}

func isSystemDir(p string) bool {
	lp := strings.ToLower(p)
	return strings.Contains(lp, `\windows\`) || strings.Contains(lp, `\program files`)
}

func isStartup(p string) bool {
	return strings.Contains(strings.ToLower(p), `\start menu\programs\startup`)
}

// underDir reports whether p lies inside dir (case-insensitive).
func underDir(p, dir string) bool {
	if dir == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(p), strings.ToLower(dir))
}

// isExternal reports whether ip is a routable, non-private remote address.
func isExternal(ip string) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return !parsed.IsLoopback() && !parsed.IsPrivate() &&
		!parsed.IsLinkLocalUnicast() && !parsed.IsUnspecified() &&
		!parsed.IsMulticast()
}

func sevRank(s Severity) int {
	switch s {
	case High:
		return 0
	case Medium:
		return 1
	case Low:
		return 2
	default:
		return 3
	}
}

func appendIf(list []Indicator, ind *Indicator) []Indicator {
	if ind == nil {
		return list
	}
	return append(list, *ind)
}

// joinSample joins up to max items, noting how many were omitted.
func joinSample(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, "\n")
	}
	shown := strings.Join(items[:max], "\n")
	return fmt.Sprintf("%s\n… +%d", shown, len(items)-max)
}
