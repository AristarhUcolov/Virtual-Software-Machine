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
	FS       []snapshot.FSChange
	Reg      []snapshot.RegChange
	Net      []netmon.Conn
	Procs    []procmon.Process
	TimedOut bool
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
	inds = appendIf(inds, droppedExecutables(in.FS, lang))
	inds = appendIf(inds, systemDirChanges(in.FS, lang))
	inds = appendIf(inds, externalNetwork(in.Net, lang))
	inds = appendIf(inds, lolbinChildren(in.Procs, lang))
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

// droppedExecutables flags freshly created executable / script files.
func droppedExecutables(fs []snapshot.FSChange, lang i18n.Lang) *Indicator {
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
		if isSystemDir(c.Path) || isStartup(c.Path) {
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
