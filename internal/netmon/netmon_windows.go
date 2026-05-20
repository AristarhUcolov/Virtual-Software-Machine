package netmon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows table classes and address families. // Классы таблиц и семейства адресов.
const (
	afInet              = 2
	afInet6             = 23
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1

	jobObjectBasicProcessIDList = 3
	errInsufficientBuffer       = 122
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	modkernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetExtendedTCPTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = modiphlpapi.NewProc("GetExtendedUdpTable")
	procQueryInfoJobObject  = modkernel32.NewProc("QueryInformationJobObject")
)

// Monitor periodically samples the connection tables of one Job Object.
// Monitor периодически опрашивает таблицы соединений одного Job Object.
type Monitor struct {
	job     windows.Handle
	rootPID uint32
	done    chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	conns   map[string]*Conn
}

// Start launches a background poller for the given job. rootPID is the main
// sandboxed process; its connections are always tracked even if the job query
// transiently fails.
//
// Start запускает фоновый опрос для указанного job. rootPID — главный процесс
// песочницы; его соединения отслеживаются всегда, даже при сбое опроса job.
func Start(job windows.Handle, rootPID uint32, interval time.Duration) *Monitor {
	if interval <= 0 {
		interval = time.Second
	}
	m := &Monitor{
		job:     job,
		rootPID: rootPID,
		done:    make(chan struct{}),
		conns:   make(map[string]*Conn),
	}
	m.wg.Add(1)
	go m.loop(interval)
	return m
}

func (m *Monitor) loop(interval time.Duration) {
	defer m.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	m.poll() // sample immediately so short-lived connections are not missed
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			m.poll()
		}
	}
}

// poll takes one sample: it reads the PID set of the job and records every
// TCP/UDP row owned by those processes.
func (m *Monitor) poll() {
	owned := map[uint32]bool{m.rootPID: true}
	for _, p := range jobProcessPIDs(m.job) {
		owned[p] = true
	}
	now := time.Now()
	rows := append(tcp4Rows(), tcp6Rows()...)
	rows = append(rows, udp4Rows()...)
	for _, c := range rows {
		if !owned[uint32(c.PID)] {
			continue
		}
		m.merge(c, now)
	}
}

// merge inserts or updates one connection in the deduplicated map.
func (m *Monitor) merge(c Conn, now time.Time) {
	key := fmt.Sprintf("%s|%s:%d|%s:%d", c.Proto, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort)
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, ok := m.conns[key]; ok {
		prev.LastSeen = now
		prev.State = c.State
		return
	}
	c.FirstSeen, c.LastSeen = now, now
	m.conns[key] = &c
}

// Stop ends polling, enriches every remote endpoint with reverse-DNS and a
// service name, and returns the sorted list of observed connections.
//
// Stop завершает опрос, дополняет каждую удалённую точку обратным DNS и
// названием сервиса и возвращает отсортированный список соединений.
func (m *Monitor) Stop() []Conn {
	close(m.done)
	m.wg.Wait()

	m.mu.Lock()
	out := make([]Conn, 0, len(m.conns))
	for _, c := range m.conns {
		out = append(out, *c)
	}
	m.mu.Unlock()

	resolveHosts(out)
	for i := range out {
		out[i].Service = serviceName(out[i].RemotePort)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		if out[i].RemoteAddr != out[j].RemoteAddr {
			return out[i].RemoteAddr < out[j].RemoteAddr
		}
		return out[i].RemotePort < out[j].RemotePort
	})
	return out
}

// AllConnections returns every TCP/UDP row currently in the system tables,
// without filtering by process. It is exposed for diagnostics.
//
// AllConnections возвращает все строки TCP/UDP из системных таблиц без
// фильтрации по процессу. Экспортируется для диагностики.
func AllConnections() []Conn {
	rows := append(tcp4Rows(), tcp6Rows()...)
	return append(rows, udp4Rows()...)
}

// jobProcessPIDs returns the process ids currently contained in job.
func jobProcessPIDs(job windows.Handle) []uint32 {
	const maxPIDs = 4096
	buf := make([]byte, 8+maxPIDs*8) // 2 DWORD header + ULONG_PTR[]
	var ret uint32
	r1, _, _ := procQueryInfoJobObject.Call(
		uintptr(job),
		jobObjectBasicProcessIDList,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&ret)),
	)
	if r1 == 0 {
		return nil
	}
	inList := *(*uint32)(unsafe.Pointer(&buf[4]))
	pids := make([]uint32, 0, inList)
	for i := uint32(0); i < inList && int(8+(i+1)*8) <= len(buf); i++ {
		v := *(*uintptr)(unsafe.Pointer(&buf[8+i*8]))
		pids = append(pids, uint32(v))
	}
	return pids
}

// queryTable calls a Get*Table function, growing the buffer until it fits.
func queryTable(proc *windows.LazyProc, af, class uintptr) []byte {
	var size uint32
	for attempt := 0; attempt < 6; attempt++ {
		proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
		if size == 0 {
			return nil
		}
		buf := make([]byte, size)
		r1, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
		if r1 == 0 {
			return buf
		}
		if r1 != errInsufficientBuffer {
			return nil
		}
		// size was updated by the call — loop and retry with a bigger buffer
	}
	return nil
}

// tcp4Rows parses the IPv4 TCP table (MIB_TCPROW_OWNER_PID, 24 bytes).
func tcp4Rows() []Conn {
	buf := queryTable(procGetExtendedTCPTable, afInet, tcpTableOwnerPIDAll)
	if buf == nil {
		return nil
	}
	const rowSz = 24
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []Conn
	for i := 0; i < int(n); i++ {
		o := 4 + i*rowSz
		if o+rowSz > len(buf) {
			break
		}
		out = append(out, Conn{
			Proto:      "TCP",
			State:      tcpState(le32(buf, o)),
			LocalAddr:  ipv4(le32(buf, o+4)),
			LocalPort:  port(le32(buf, o+8)),
			RemoteAddr: ipv4(le32(buf, o+12)),
			RemotePort: port(le32(buf, o+16)),
			PID:        int(le32(buf, o+20)),
		})
	}
	return out
}

// tcp6Rows parses the IPv6 TCP table (MIB_TCP6ROW_OWNER_PID, 56 bytes).
func tcp6Rows() []Conn {
	buf := queryTable(procGetExtendedTCPTable, afInet6, tcpTableOwnerPIDAll)
	if buf == nil {
		return nil
	}
	const rowSz = 56
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []Conn
	for i := 0; i < int(n); i++ {
		o := 4 + i*rowSz
		if o+rowSz > len(buf) {
			break
		}
		out = append(out, Conn{
			Proto:      "TCP",
			LocalAddr:  ipv6(buf[o : o+16]),
			LocalPort:  port(le32(buf, o+20)),
			RemoteAddr: ipv6(buf[o+24 : o+40]),
			RemotePort: port(le32(buf, o+44)),
			State:      tcpState(le32(buf, o+48)),
			PID:        int(le32(buf, o+52)),
		})
	}
	return out
}

// udp4Rows parses the IPv4 UDP table (MIB_UDPROW_OWNER_PID, 12 bytes).
func udp4Rows() []Conn {
	buf := queryTable(procGetExtendedUDPTable, afInet, udpTableOwnerPID)
	if buf == nil {
		return nil
	}
	const rowSz = 12
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []Conn
	for i := 0; i < int(n); i++ {
		o := 4 + i*rowSz
		if o+rowSz > len(buf) {
			break
		}
		out = append(out, Conn{
			Proto:     "UDP",
			State:     "—",
			LocalAddr: ipv4(le32(buf, o)),
			LocalPort: port(le32(buf, o+4)),
			PID:       int(le32(buf, o+8)),
		})
	}
	return out
}

// resolveHosts fills Host with the reverse-DNS name of each remote address.
func resolveHosts(conns []Conn) {
	cache := map[string]string{}
	for i := range conns {
		ip := conns[i].RemoteAddr
		if ip == "" || ip == "0.0.0.0" || ip == "::" {
			continue
		}
		if h, ok := cache[ip]; ok {
			conns[i].Host = h
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		names, err := net.DefaultResolver.LookupAddr(ctx, ip)
		cancel()
		h := ""
		if err == nil && len(names) > 0 {
			h = names[0]
		}
		cache[ip] = h
		conns[i].Host = h
	}
}

// le32 reads a little-endian uint32 at offset o.
func le32(b []byte, o int) uint32 {
	return uint32(b[o]) | uint32(b[o+1])<<8 | uint32(b[o+2])<<16 | uint32(b[o+3])<<24
}

// ipv4 formats a network-byte-order IPv4 DWORD.
func ipv4(d uint32) string {
	return net.IPv4(byte(d), byte(d>>8), byte(d>>16), byte(d>>24)).String()
}

// ipv6 formats a 16-byte IPv6 address.
func ipv6(b []byte) string {
	ip := make(net.IP, 16)
	copy(ip, b)
	return ip.String()
}

// port converts a network-byte-order port DWORD to a host-order port.
func port(d uint32) uint16 {
	return uint16(d&0xff)<<8 | uint16((d>>8)&0xff)
}

// tcpState maps a MIB_TCP_STATE numeric value to its name.
func tcpState(s uint32) string {
	switch s {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN-SENT"
	case 4:
		return "SYN-RCVD"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN-WAIT1"
	case 7:
		return "FIN-WAIT2"
	case 8:
		return "CLOSE-WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST-ACK"
	case 11:
		return "TIME-WAIT"
	case 12:
		return "DELETE-TCB"
	default:
		return fmt.Sprintf("STATE-%d", s)
	}
}

// serviceName returns a well-known service label for common ports.
func serviceName(p uint16) string {
	switch p {
	case 20, 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25, 587:
		return "SMTP"
	case 53:
		return "DNS"
	case 67, 68:
		return "DHCP"
	case 80, 8080:
		return "HTTP"
	case 110:
		return "POP3"
	case 123:
		return "NTP"
	case 143:
		return "IMAP"
	case 161, 162:
		return "SNMP"
	case 389:
		return "LDAP"
	case 443, 8443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 465:
		return "SMTPS"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 1080:
		return "SOCKS"
	case 1433:
		return "MSSQL"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 9001, 9030, 9050, 9051:
		return "Tor"
	default:
		return ""
	}
}
