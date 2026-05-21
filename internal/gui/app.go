// Package gui implements the Fyne desktop interface of the Virtual Software
// Machine. It builds a single bilingual window from which a user picks a
// file, runs it inside the sandbox and opens the resulting forensic report.
//
// Пакет gui реализует десктопный интерфейс на Fyne. Он строит одно двуязычное
// окно, из которого пользователь выбирает файл, запускает его в песочнице и
// открывает полученный криминалистический отчёт.
package gui

import (
	"image/color"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"vsm/internal/config"
	"vsm/internal/i18n"
	"vsm/internal/sandbox"
	"vsm/internal/wsb"
)

type ui struct {
	win  fyne.Window
	lang i18n.Lang

	title      *widget.Label
	subtitle   *widget.Label
	langLabel  *widget.Label
	langSelect *widget.Select
	targetLbl  *widget.Label
	targetEnt  *widget.Entry
	browseBtn  *widget.Button
	argsLbl    *widget.Label
	argsEnt    *widget.Entry
	timeoutLbl *widget.Label
	timeoutEnt *widget.Entry
	lowChk     *widget.Check
	wsbChk     *widget.Check
	runBtn     *widget.Button
	openRepBtn *widget.Button
	openDirBtn *widget.Button
	status     *widget.Label
	verdict    *canvas.Text
	logLbl     *widget.Label
	disclaimer *widget.Label

	lastResult *sandbox.Result
}

// Run builds the window and enters the Fyne event loop.
// Run строит окно и запускает цикл событий Fyne.
func Run() {
	a := fyneapp.New()
	w := a.NewWindow("Virtual Software Machine")

	u := &ui{win: w, lang: i18n.RU}
	u.build()
	u.applyLang()

	w.Resize(fyne.NewSize(940, 720))
	w.SetContent(u.content())
	w.ShowAndRun()
}

func (u *ui) build() {
	u.title = widget.NewLabel("")
	u.title.TextStyle = fyne.TextStyle{Bold: true}
	u.subtitle = widget.NewLabel("")

	u.langLabel = widget.NewLabel("")
	u.langSelect = widget.NewSelect([]string{"Русский", "English"}, func(s string) {
		if s == "English" {
			u.lang = i18n.EN
		} else {
			u.lang = i18n.RU
		}
		u.applyLang()
	})
	u.langSelect.Selected = "Русский" // set without firing OnChanged (widgets not built yet)

	u.targetLbl = widget.NewLabel("")
	u.targetEnt = widget.NewEntry()
	u.browseBtn = widget.NewButton("", u.onBrowse)

	u.argsLbl = widget.NewLabel("")
	u.argsEnt = widget.NewEntry()

	u.timeoutLbl = widget.NewLabel("")
	u.timeoutEnt = widget.NewEntry()
	u.timeoutEnt.SetText("120")

	u.lowChk = widget.NewCheck("", nil)
	u.lowChk.SetChecked(true)

	u.wsbChk = widget.NewCheck("", nil)

	u.runBtn = widget.NewButton("", u.onRun)
	u.runBtn.Importance = widget.HighImportance

	u.openRepBtn = widget.NewButton("", u.onOpenReport)
	u.openRepBtn.Disable()
	u.openDirBtn = widget.NewButton("", u.onOpenDir)
	u.openDirBtn.Disable()

	u.status = widget.NewLabel("")
	u.verdict = canvas.NewText("", color.White)
	u.verdict.TextStyle = fyne.TextStyle{Bold: true}
	u.verdict.TextSize = 16
	u.logLbl = widget.NewLabel("")
	u.logLbl.Wrapping = fyne.TextWrapBreak
	u.disclaimer = widget.NewLabel("")
	u.disclaimer.Wrapping = fyne.TextWrapWord
}

func (u *ui) content() fyne.CanvasObject {
	header := container.NewVBox(u.title, u.subtitle, widget.NewSeparator())

	form := container.New(layoutForm(),
		u.langLabel, u.langSelect,
		u.targetLbl, container.NewBorder(nil, nil, nil, u.browseBtn, u.targetEnt),
		u.argsLbl, u.argsEnt,
		u.timeoutLbl, u.timeoutEnt,
		widget.NewLabel(""), u.lowChk,
		widget.NewLabel(""), u.wsbChk,
	)

	actions := container.NewHBox(u.runBtn, u.openRepBtn, u.openDirBtn)
	top := container.NewVBox(header, form, actions, u.status, u.verdict, widget.NewSeparator())
	bottom := container.NewVBox(widget.NewSeparator(), u.disclaimer)
	logScroll := container.NewVScroll(u.logLbl)

	return container.NewBorder(top, bottom, nil, nil, logScroll)
}

// applyLang refreshes every visible string for the current language.
func (u *ui) applyLang() {
	t := func(k string) string { return i18n.T(u.lang, k) }
	u.win.SetTitle(t("app.title"))
	u.title.SetText(t("app.title"))
	u.subtitle.SetText(t("app.subtitle"))
	u.langLabel.SetText(t("lang.label"))
	u.targetLbl.SetText(t("field.target"))
	u.browseBtn.SetText(t("field.browse"))
	u.argsLbl.SetText(t("field.args"))
	u.timeoutLbl.SetText(t("field.timeout"))
	u.lowChk.Text = t("field.lowint")
	u.lowChk.Refresh()
	u.wsbChk.Text = t("field.wsb")
	u.wsbChk.Refresh()
	u.runBtn.SetText(t("field.run"))
	u.openRepBtn.SetText(t("field.openrep"))
	u.openDirBtn.SetText(t("field.opendir"))
	u.disclaimer.SetText(t("disclaimer"))
	if u.status.Text == "" {
		u.status.SetText(t("status.idle"))
	}
}

func (u *ui) onBrowse() {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil || r == nil {
			return
		}
		defer r.Close()
		u.targetEnt.SetText(normalizePath(r.URI().Path()))
	}, u.win)
}

func (u *ui) onRun() {
	target := strings.TrimSpace(u.targetEnt.Text)
	if target == "" {
		dialog.ShowInformation(i18n.T(u.lang, "status.error"),
			i18n.T(u.lang, "msg.notarget"), u.win)
		return
	}
	if u.wsbChk.Checked {
		u.runViaWSB(target)
		return
	}
	timeout, err := strconv.Atoi(strings.TrimSpace(u.timeoutEnt.Text))
	if err != nil || timeout < 0 {
		timeout = 120
	}

	cfg := config.Default(string(u.lang))
	cfg.TimeoutSec = timeout
	cfg.LowIntegrity = u.lowChk.Checked

	opts := sandbox.Options{TargetPath: target}
	if a := strings.TrimSpace(u.argsEnt.Text); a != "" {
		opts.Args = strings.Fields(a)
	}

	u.runBtn.Disable()
	u.openRepBtn.Disable()
	u.openDirBtn.Disable()
	u.logLbl.SetText("")
	u.clearVerdict()
	u.setStatus("status.prepare")

	go func() {
		res, runErr := sandbox.Run(cfg, opts, u.appendLog)
		u.runBtn.Enable()
		if runErr != nil {
			u.status.SetText(i18n.T(u.lang, "status.error") + ": " + runErr.Error())
			return
		}
		u.lastResult = res
		u.openRepBtn.Enable()
		u.openDirBtn.Enable()
		r := res.Report
		u.showVerdict(r.Analysis.Level, r.Analysis.LevelText, r.Analysis.Score)
		u.appendLog("═══ " + i18n.T(u.lang, "msg.verdict") + ": " + r.Analysis.LevelText +
			" (" + strconv.Itoa(r.Analysis.Score) + "/100) ═══")
		for _, ind := range r.Analysis.Indicators {
			u.appendLog("  [" + i18n.T(u.lang, "sev."+string(ind.Severity)) + "] " + ind.Title)
		}
		var fpCount, sysCount int
		for _, c := range r.FSChanges {
			if r.InSandbox(c.Path) {
				fpCount++
			} else {
				sysCount++
			}
		}
		u.appendLog(i18n.T(u.lang, "msg.footprintcount", fpCount))
		u.appendLog(i18n.T(u.lang, "msg.syscount", sysCount))
		u.appendLog(i18n.T(u.lang, "msg.regcount", len(r.RegChanges)))
		u.appendLog(i18n.T(u.lang, "msg.evcount", len(r.Timeline)))
		u.appendLog(i18n.T(u.lang, "msg.netcount", len(r.Network)))
		for _, c := range r.Network {
			if c.RemoteAddr != "" && c.RemoteAddr != "0.0.0.0" && c.RemoteAddr != "::" {
				u.appendLog("  → " + c.Proto + " " + c.RemoteAddr + ":" +
					strconv.Itoa(int(c.RemotePort)) + " " + c.State + " " + c.Service + " " + c.Host)
			}
		}
		u.appendLog(i18n.T(u.lang, "msg.dnscount", len(r.DNSQueries)))
		for _, d := range r.DNSQueries {
			u.appendLog("  · " + d)
		}
		u.appendLog("IOC: " + res.IOCPath)
		u.appendLog("STIX: " + res.STIXPath)
		u.appendLog(i18n.T(u.lang, "msg.proccount", len(r.Processes)))
		for _, p := range r.Processes {
			role := i18n.T(u.lang, "label.child")
			if p.IsRoot {
				role = i18n.T(u.lang, "label.roottarget")
			}
			u.appendLog("  • pid=" + strconv.Itoa(p.PID) + " [" + role + "] " + p.Image)
			if p.CommandLine != "" {
				u.appendLog("      " + p.CommandLine)
			}
		}
		u.setStatus("status.done")
	}()
}

// runViaWSB prepares the analysis for Windows Sandbox and launches it when the
// feature is installed; otherwise it shows the honest fallback in the log.
//
// runViaWSB готовит анализ для Windows Sandbox и запускает его, если функция
// установлена; иначе показывает честное сообщение в журнале.
func (u *ui) runViaWSB(target string) {
	u.runBtn.Disable()
	u.openRepBtn.Disable()
	u.openDirBtn.Disable()
	u.logLbl.SetText("")
	u.clearVerdict()
	u.setStatus("wsb.preparing")

	go func() {
		defer u.runBtn.Enable()
		base := config.Default(string(u.lang))
		wsbPath, reportDir, err := wsb.Prepare(target, string(u.lang), base.WorkspaceDir)
		if err != nil {
			u.status.SetText(i18n.T(u.lang, "status.error") + ": " + err.Error())
			return
		}
		u.appendLog("WSB: " + wsbPath)
		u.appendLog(i18n.T(u.lang, "wsb.reportdir") + ": " + reportDir)
		if !wsb.Available() {
			u.appendLog(i18n.T(u.lang, "wsb.unavailable"))
			u.setStatus("status.idle")
			return
		}
		u.appendLog(i18n.T(u.lang, "wsb.launching"))
		if err := exec.Command(wsb.ExePath(), wsbPath).Start(); err != nil {
			u.status.SetText(i18n.T(u.lang, "status.error") + ": " + err.Error())
			return
		}
		u.appendLog(i18n.T(u.lang, "wsb.done"))
		u.setStatus("status.done")
	}()
}

// showVerdict paints the coloured verdict banner after an analysis.
// showVerdict показывает цветной баннер вердикта после анализа.
func (u *ui) showVerdict(level, text string, score int) {
	switch level {
	case "dangerous":
		u.verdict.Color = color.RGBA{R: 0xef, G: 0x53, B: 0x50, A: 0xff}
	case "suspicious":
		u.verdict.Color = color.RGBA{R: 0xff, G: 0xb3, B: 0x00, A: 0xff}
	default:
		u.verdict.Color = color.RGBA{R: 0x4c, G: 0xaf, B: 0x50, A: 0xff}
	}
	u.verdict.Text = "■ " + i18n.T(u.lang, "msg.verdict") + ": " + text +
		"  (" + strconv.Itoa(score) + "/100)"
	u.verdict.Refresh()
}

// clearVerdict blanks the verdict banner before a new run.
func (u *ui) clearVerdict() {
	u.verdict.Text = ""
	u.verdict.Refresh()
}

// appendLog adds one line to the log view, translating "status:*" markers.
func (u *ui) appendLog(s string) {
	if rest, ok := strings.CutPrefix(s, "status:"); ok {
		u.status.SetText(i18n.T(u.lang, "status."+rest))
		s = i18n.T(u.lang, "status."+rest)
	}
	u.logLbl.SetText(u.logLbl.Text + s + "\n")
}

func (u *ui) setStatus(key string) { u.status.SetText(i18n.T(u.lang, key)) }

func (u *ui) onOpenReport() {
	if u.lastResult != nil {
		openInShell(u.lastResult.HTMLPath)
	}
}

func (u *ui) onOpenDir() {
	if u.lastResult != nil {
		openInShell(u.lastResult.SessionDir)
	}
}

// openInShell opens a file or folder with the Windows shell default handler.
func openInShell(path string) {
	_ = exec.Command("explorer", filepath.Clean(path)).Start()
}

// normalizePath converts a Fyne file-URI path ("/C:/dir/file") to a native
// Windows path. // normalizePath приводит путь file-URI Fyne к виду Windows.
func normalizePath(p string) string {
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p)
}

// layoutForm returns a two-column grid used for the input form.
func layoutForm() fyne.Layout {
	return &formLayout{}
}

type formLayout struct{}

func (f *formLayout) MinSize(objs []fyne.CanvasObject) fyne.Size {
	var w, h float32
	for i := 0; i < len(objs); i += 2 {
		row := objs[i].MinSize().Height
		if i+1 < len(objs) {
			if rh := objs[i+1].MinSize().Height; rh > row {
				row = rh
			}
		}
		h += row + 6
	}
	w = 760
	return fyne.NewSize(w, h)
}

func (f *formLayout) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	const labelW float32 = 240
	var y float32
	for i := 0; i < len(objs); i += 2 {
		rowH := objs[i].MinSize().Height
		if i+1 < len(objs) {
			if rh := objs[i+1].MinSize().Height; rh > rowH {
				rowH = rh
			}
		}
		objs[i].Move(fyne.NewPos(0, y))
		objs[i].Resize(fyne.NewSize(labelW, rowH))
		if i+1 < len(objs) {
			objs[i+1].Move(fyne.NewPos(labelW+10, y))
			objs[i+1].Resize(fyne.NewSize(size.Width-labelW-10, rowH))
		}
		y += rowH + 6
	}
}
