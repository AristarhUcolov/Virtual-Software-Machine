// Package dnsmon reads the Windows DNS resolver cache so a sandbox session can
// report the domain names resolved while the analysed program ran — without
// ETW and without administrator rights.
//
// It snapshots the cache before and after the run; the difference is the set
// of names newly resolved during the analysis. The cache is system-wide, so
// the result can include background OS activity — the same honest trade-off
// the file-system snapshot diff already makes.
//
// Пакет dnsmon читает кэш DNS-резолвера Windows, чтобы сессия песочницы могла
// сообщить доменные имена, разрешённые во время работы программы — без ETW и
// без прав администратора. Кэш системный, поэтому возможен фоновый шум.
package dnsmon

import (
	"sort"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxCacheWalk = 8192 // safety cap on the linked-list walk

var (
	moddnsapi                = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsGetCacheDataTable = moddnsapi.NewProc("DnsGetCacheDataTable")
)

// Snapshot returns the set of host names currently in the DNS resolver cache,
// lower-cased. It walks the DNS_CACHE_ENTRY linked list returned by
// dnsapi!DnsGetCacheDataTable — the same data source as `ipconfig /displaydns`.
//
// Snapshot возвращает множество имён из кэша DNS-резолвера (в нижнем регистре).
func Snapshot() map[string]bool {
	names := make(map[string]bool)

	// DNS_CACHE_ENTRY (x64 layout): pNext @0, pszName @8, wType @16,
	// wDataLength @18, dwFlags @20 — 24 bytes total.
	var head [24]byte
	r1, _, _ := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head[0])))
	if r1 == 0 {
		return names // call failed or unsupported — no walk, no risk
	}
	node := *(*uintptr)(unsafe.Pointer(&head[0])) // head.pNext = list head

	for i := 0; node != 0 && i < maxCacheWalk; i++ {
		entry, ok := readMem(node, 24)
		if !ok {
			break
		}
		next := *(*uintptr)(unsafe.Pointer(&entry[0]))
		namePtr := *(*uintptr)(unsafe.Pointer(&entry[8]))
		if namePtr != 0 {
			if name := strings.TrimSpace(strings.ToLower(readWString(namePtr))); name != "" {
				names[name] = true
			}
		}
		node = next
	}
	return names
}

// Diff returns the host names present in after but not in before — the names
// resolved while the sandboxed program was running.
//
// Diff возвращает имена, появившиеся в after, но отсутствующие в before.
func Diff(before, after map[string]bool) []string {
	var out []string
	for name := range after {
		if !before[name] {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// readMem reads n bytes from this process at addr via ReadProcessMemory, which
// avoids any uintptr-to-pointer conversion of the OS-owned cache memory.
func readMem(addr uintptr, n int) ([]byte, bool) {
	buf := make([]byte, n)
	var got uintptr
	err := windows.ReadProcessMemory(windows.CurrentProcess(), addr, &buf[0], uintptr(n), &got)
	return buf, err == nil && got == uintptr(n)
}

// readWString reads a NUL-terminated UTF-16 string from addr.
func readWString(addr uintptr) string {
	for _, size := range []int{256, 64, 16} {
		if b, ok := readMem(addr, size); ok {
			return decodeUTF16Z(b)
		}
	}
	return ""
}

// decodeUTF16Z decodes little-endian UTF-16 from b, stopping at the first NUL.
func decodeUTF16Z(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
