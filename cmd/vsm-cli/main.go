// Command vsm-cli is the console front-end of the Virtual Software Machine.
// It needs no C compiler and is handy for scripted / headless analysis.
//
// Команда vsm-cli — консольный интерфейс Virtual Software Machine. Не требует
// компилятора C и удобна для скриптового / безголового анализа.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"vsm/internal/config"
	"vsm/internal/i18n"
	"vsm/internal/netmon"
	"vsm/internal/sandbox"
	"vsm/internal/wsb"
)

func main() {
	lang := flag.String("lang", "ru", "interface language / язык: ru|en")
	target := flag.String("target", "", "path to the file/.exe to analyse / путь к файлу")
	timeout := flag.Int("timeout", 120, "timeout in seconds / таймаут, сек")
	low := flag.Bool("low", true, "run at Low integrity / низкая целостность")
	args := flag.String("args", "", "arguments for the target / аргументы")
	out := flag.String("out", "", "report output directory / папка для отчёта")
	useWSB := flag.Bool("wsb", false, "analyse inside Windows Sandbox / анализ в Windows Sandbox")
	netdump := flag.Int("netdump", 0, "diagnostic: dump connection tables N times")
	flag.Parse()

	if *netdump > 0 {
		for i := 0; i < *netdump; i++ {
			conns := netmon.AllConnections()
			fmt.Printf("--- sample %d: %d rows ---\n", i, len(conns))
			for _, c := range conns {
				if c.Proto == "TCP" {
					fmt.Printf("  %s pid=%d %s:%d -> %s:%d %s\n",
						c.Proto, c.PID, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort, c.State)
				}
			}
			time.Sleep(time.Second)
		}
		return
	}

	l := i18n.Normalize(*lang)
	if *target == "" {
		fmt.Fprintln(os.Stderr, i18n.T(l, "msg.notarget"))
		flag.Usage()
		os.Exit(2)
	}
	if _, err := os.Stat(*target); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T(l, "msg.nofile", *target))
		os.Exit(2)
	}

	if *useWSB {
		runViaWindowsSandbox(l, *target)
		return
	}

	cfg := config.Default(string(l))
	cfg.TimeoutSec = *timeout
	cfg.LowIntegrity = *low
	if *out != "" {
		cfg.WorkspaceDir = *out
	}

	fmt.Println("=== " + i18n.T(l, "app.title") + " ===")
	fmt.Println(i18n.T(l, "disclaimer"))
	fmt.Println(strings.Repeat("-", 70))

	opts := sandbox.Options{TargetPath: *target}
	if *args != "" {
		opts.Args = strings.Fields(*args)
	}

	start := time.Now()
	res, err := sandbox.Run(cfg, opts, func(s string) {
		fmt.Println("  " + translateStatus(l, s))
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T(l, "status.error")+": "+err.Error())
		os.Exit(1)
	}

	r := res.Report
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("%s: %s  [%s %d/100]\n", i18n.T(l, "msg.verdict"),
		r.Analysis.LevelText, i18n.T(l, "label.score"), r.Analysis.Score)
	for _, ind := range r.Analysis.Indicators {
		fmt.Printf("  [%s] %s\n", i18n.T(l, "sev."+string(ind.Severity)), ind.Title)
	}
	fmt.Println(strings.Repeat("-", 70))
	var fpCount, sysCount int
	for _, c := range r.FSChanges {
		if r.InSandbox(c.Path) {
			fpCount++
		} else {
			sysCount++
		}
	}
	fmt.Println(i18n.T(l, "msg.footprintcount", fpCount))
	fmt.Println(i18n.T(l, "msg.syscount", sysCount))
	fmt.Println(i18n.T(l, "msg.regcount", len(r.RegChanges)))
	fmt.Println(i18n.T(l, "msg.evcount", len(r.Timeline)))
	fmt.Println(i18n.T(l, "msg.netcount", len(r.Network)))
	for _, c := range r.Network {
		if c.RemoteAddr != "" && c.RemoteAddr != "0.0.0.0" && c.RemoteAddr != "::" {
			fmt.Printf("  → %s %s:%d %s %s %s\n", c.Proto, c.RemoteAddr, c.RemotePort, c.State, c.Service, c.Host)
		}
	}
	fmt.Println(i18n.T(l, "msg.proccount", len(r.Processes)))
	for _, p := range r.Processes {
		role := "child"
		if p.IsRoot {
			role = "root"
		}
		fmt.Printf("  • pid=%d [%s] %s\n", p.PID, role, p.Image)
		if p.CommandLine != "" {
			fmt.Printf("      %s\n", p.CommandLine)
		}
	}
	fmt.Printf("%s: %s\n", i18n.T(l, "label.duration"), time.Since(start).Round(time.Millisecond))
	fmt.Println("HTML : " + res.HTMLPath)
	fmt.Println("JSON : " + res.JSONPath)
	fmt.Println("IOC  : " + res.IOCPath)
	fmt.Println("STIX : " + res.STIXPath)
}

// runViaWindowsSandbox stages the analysis for Windows Sandbox and launches it
// when the feature is installed; otherwise it reports an honest fallback.
//
// runViaWindowsSandbox готовит анализ для Windows Sandbox и запускает его, если
// функция установлена; иначе выдаёт честное сообщение с инструкцией.
func runViaWindowsSandbox(l i18n.Lang, target string) {
	fmt.Println("=== " + i18n.T(l, "app.title") + " ===")
	fmt.Println(i18n.T(l, "wsb.preparing"))

	base := config.Default(string(l))
	wsbPath, reportDir, err := wsb.Prepare(target, string(l), base.WorkspaceDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T(l, "status.error")+": "+err.Error())
		os.Exit(1)
	}
	fmt.Println("WSB    : " + wsbPath)
	fmt.Println(i18n.T(l, "wsb.reportdir") + ": " + reportDir)

	if !wsb.Available() {
		fmt.Println()
		fmt.Println(i18n.T(l, "wsb.unavailable"))
		return
	}
	fmt.Println(i18n.T(l, "wsb.launching"))
	if err := exec.Command(wsb.ExePath(), wsbPath).Start(); err != nil {
		fmt.Fprintln(os.Stderr, i18n.T(l, "status.error")+": "+err.Error())
		os.Exit(1)
	}
	fmt.Println(i18n.T(l, "wsb.done"))
}

// translateStatus converts a "status:key" progress marker into a localized
// message, leaving plain log lines untouched.
func translateStatus(l i18n.Lang, s string) string {
	if rest, ok := strings.CutPrefix(s, "status:"); ok {
		return i18n.T(l, "status."+rest)
	}
	return s
}
