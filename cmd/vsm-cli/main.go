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
	"strings"
	"time"

	"vsm/internal/config"
	"vsm/internal/i18n"
	"vsm/internal/netmon"
	"vsm/internal/sandbox"
)

func main() {
	lang := flag.String("lang", "ru", "interface language / язык: ru|en")
	target := flag.String("target", "", "path to the file/.exe to analyse / путь к файлу")
	timeout := flag.Int("timeout", 120, "timeout in seconds / таймаут, сек")
	low := flag.Bool("low", true, "run at Low integrity / низкая целостность")
	args := flag.String("args", "", "arguments for the target / аргументы")
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

	cfg := config.Default(string(l))
	cfg.TimeoutSec = *timeout
	cfg.LowIntegrity = *low

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
	fmt.Println(i18n.T(l, "msg.fscount", len(r.FSChanges)))
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
	}
	fmt.Printf("%s: %s\n", i18n.T(l, "label.duration"), time.Since(start).Round(time.Millisecond))
	fmt.Println("HTML : " + res.HTMLPath)
	fmt.Println("JSON : " + res.JSONPath)
}

// translateStatus converts a "status:key" progress marker into a localized
// message, leaving plain log lines untouched.
func translateStatus(l i18n.Lang, s string) string {
	if rest, ok := strings.CutPrefix(s, "status:"); ok {
		return i18n.T(l, "status."+rest)
	}
	return s
}
