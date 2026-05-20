package report

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"vsm/internal/snapshot"
)

// WriteIOCs writes a portable plain-text Indicators-of-Compromise sheet next
// to the report. The format is intentionally simple — one indicator per line,
// grouped by type — so it can be pasted straight into VirusTotal, a blocklist
// or a threat-intel feed.
//
// WriteIOCs сохраняет рядом с отчётом портативный текстовый список индикаторов
// компрометации (IOC): один индикатор на строку, сгруппировано по типам —
// чтобы его можно было сразу вставить в VirusTotal, блоклист или threat-feed.
func (r *SessionReport) WriteIOCs(path string) error {
	var b strings.Builder
	line := func(s string) { b.WriteString(s); b.WriteByte('\n') }

	line("# Virtual Software Machine " + r.Version + " — Indicators of Compromise")
	line("# target   : " + r.Target.Path)
	line("# sha256   : " + r.Target.SHA256)
	line("# verdict  : " + r.Analysis.Level + fmt.Sprintf(" (score %d/100)", r.Analysis.Score))
	line("# generated: " + r.GeneratedAt.Format(time.RFC3339))
	line("")

	// File hashes of files the program itself created. Only the in-sandbox
	// footprint is exported, so the IOC sheet stays high-confidence and free
	// of unrelated OS background activity caught by the snapshot diff.
	// SHA-256 файлов, созданных самой программой (только след в песочнице).
	type hash struct{ sum, path string }
	var hashes []hash
	var dropped []string
	for _, c := range r.FSChanges {
		if c.Type != snapshot.Added || c.After == nil || !r.InSandbox(c.Path) {
			continue
		}
		dropped = append(dropped, c.Path)
		if c.After.SHA256 != "" {
			hashes = append(hashes, hash{c.After.SHA256, c.Path})
		}
	}
	if len(hashes) > 0 {
		line("## file-sha256")
		sort.Slice(hashes, func(i, j int) bool { return hashes[i].sum < hashes[j].sum })
		for _, h := range hashes {
			line(h.sum + "  " + h.path)
		}
		line("")
	}

	// External IP addresses and domains. // Внешние IP-адреса и домены.
	ips := newSet()
	domains := newSet()
	for _, c := range r.Network {
		if !isExternalIP(c.RemoteAddr) {
			continue // loopback / private endpoints are not shareable IOCs
		}
		ips.add(c.RemoteAddr)
		if c.Host != "" {
			domains.add(strings.TrimRight(c.Host, "."))
		}
	}
	if v := ips.sorted(); len(v) > 0 {
		line("## network-ip")
		for _, s := range v {
			line(s)
		}
		line("")
	}
	if v := domains.sorted(); len(v) > 0 {
		line("## network-domain")
		for _, s := range v {
			line(s)
		}
		line("")
	}

	// Registry autorun entries. // Записи автозапуска в реестре.
	autoruns := newSet()
	for _, c := range r.RegChanges {
		if c.Type == snapshot.Deleted {
			continue
		}
		k := strings.ToLower(c.KeyPath)
		if strings.Contains(k, `currentversion\run`) || strings.Contains(k, "winlogon") {
			autoruns.add(c.KeyPath + `\` + c.ValueName)
		}
	}
	if v := autoruns.sorted(); len(v) > 0 {
		line("## registry-autorun")
		for _, s := range v {
			line(s)
		}
		line("")
	}

	// Created / dropped file paths. // Пути созданных файлов.
	if len(dropped) > 0 {
		line("## dropped-file")
		sort.Strings(dropped)
		for _, p := range dropped {
			line(p)
		}
		line("")
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// isExternalIP reports whether ip is a routable, non-private remote address.
func isExternalIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return !parsed.IsLoopback() && !parsed.IsPrivate() &&
		!parsed.IsLinkLocalUnicast() && !parsed.IsUnspecified() && !parsed.IsMulticast()
}

// set is a tiny ordered-unique string collector.
type set struct{ m map[string]bool }

func newSet() *set { return &set{m: map[string]bool{}} }

func (s *set) add(v string) {
	if v != "" {
		s.m[v] = true
	}
}

func (s *set) sorted() []string {
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
