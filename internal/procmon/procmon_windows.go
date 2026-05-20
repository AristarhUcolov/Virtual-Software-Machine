package procmon

import (
	"sort"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	jobObjectBasicProcessIDList = 3
)

var (
	modkernel32            = windows.NewLazySystemDLL("kernel32.dll")
	procQueryInfoJobObject = modkernel32.NewProc("QueryInformationJobObject")
	modntdll               = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInfoProcess = modntdll.NewProc("NtQueryInformationProcess")
)

// x64 structure offsets used to read a process command line from its PEB.
// These offsets are stable across Windows 10 / 11 x64.
const (
	pbiPebOffset      = 8    // PROCESS_BASIC_INFORMATION.PebBaseAddress
	pebParamsOffset   = 0x20 // PEB.ProcessParameters
	paramsCmdLine     = 0x70 // RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING)
	maxCommandLineLen = 0x8000
)

// Monitor periodically samples the process list of one Job Object.
// Monitor периодически опрашивает список процессов одного Job Object.
type Monitor struct {
	job     windows.Handle
	rootPID uint32
	done    chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	procs   map[uint32]*Process
}

// Start launches a background process poller for the given job. rootPID marks
// the analysed target so the report can distinguish it from spawned children.
//
// Start запускает фоновый опрос процессов для указанного job. rootPID
// помечает анализируемую цель, чтобы отличать её от порождённых потомков.
func Start(job windows.Handle, rootPID uint32, interval time.Duration) *Monitor {
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	m := &Monitor{
		job:     job,
		rootPID: rootPID,
		done:    make(chan struct{}),
		procs:   make(map[uint32]*Process),
	}
	m.wg.Add(1)
	go m.loop(interval)
	return m
}

func (m *Monitor) loop(interval time.Duration) {
	defer m.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	m.poll()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			m.poll()
		}
	}
}

// poll records every PID currently in the job (plus the root PID), resolving
// the executable path the first time a PID is seen.
func (m *Monitor) poll() {
	pids := append(jobPIDs(m.job), m.rootPID)
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		if p, ok := m.procs[pid]; ok {
			p.LastSeen = now
			continue
		}
		m.procs[pid] = &Process{
			PID:         int(pid),
			Image:       imageName(pid),
			CommandLine: commandLine(pid),
			IsRoot:      pid == m.rootPID,
			FirstSeen:   now,
			LastSeen:    now,
		}
	}
}

// Stop ends polling and returns the observed processes, root first.
// Stop завершает опрос и возвращает замеченные процессы, корневой — первым.
func (m *Monitor) Stop() []Process {
	close(m.done)
	m.wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Process, 0, len(m.procs))
	for _, p := range m.procs {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsRoot != out[j].IsRoot {
			return out[i].IsRoot // root process first
		}
		return out[i].FirstSeen.Before(out[j].FirstSeen)
	})
	return out
}

// jobPIDs returns the process ids currently contained in job.
func jobPIDs(job windows.Handle) []uint32 {
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

// imageName resolves the full executable path of a process id.
func imageName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// commandLine reads the full command line of a process by walking its PEB:
// PROCESS_BASIC_INFORMATION -> PEB -> ProcessParameters -> CommandLine.
// Any failure (process gone, access denied, 32-bit layout) yields "".
//
// commandLine читает командную строку процесса, обходя его PEB. Любая
// ошибка (процесс завершился, нет доступа) даёт "".
func commandLine(pid uint32) string {
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var pbi [48]byte // PROCESS_BASIC_INFORMATION (x64)
	var retLen uint32
	r1, _, _ := procNtQueryInfoProcess.Call(
		uintptr(h), 0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi[0])), uintptr(len(pbi)),
		uintptr(unsafe.Pointer(&retLen)))
	if r1 != 0 { // NTSTATUS != STATUS_SUCCESS
		return ""
	}
	peb := *(*uintptr)(unsafe.Pointer(&pbi[pbiPebOffset]))
	if peb == 0 {
		return ""
	}
	params, ok := readPtr(h, peb+pebParamsOffset)
	if !ok || params == 0 {
		return ""
	}
	// CommandLine UNICODE_STRING: Length (u16 @0), Buffer (ptr @8).
	var us [16]byte
	if !readMem(h, params+paramsCmdLine, us[:]) {
		return ""
	}
	length := *(*uint16)(unsafe.Pointer(&us[0]))
	buf := *(*uintptr)(unsafe.Pointer(&us[8]))
	if length == 0 || buf == 0 || length > maxCommandLineLen {
		return ""
	}
	raw := make([]byte, length)
	if !readMem(h, buf, raw) {
		return ""
	}
	u16 := make([]uint16, length/2)
	for i := range u16 {
		u16[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return windows.UTF16ToString(u16)
}

// readPtr reads one pointer-sized value from another process.
func readPtr(h windows.Handle, addr uintptr) (uintptr, bool) {
	var b [8]byte
	if !readMem(h, addr, b[:]) {
		return 0, false
	}
	return *(*uintptr)(unsafe.Pointer(&b[0])), true
}

// readMem reads len(buf) bytes from another process at addr.
func readMem(h windows.Handle, addr uintptr, buf []byte) bool {
	var n uintptr
	err := windows.ReadProcessMemory(h, addr, &buf[0], uintptr(len(buf)), &n)
	return err == nil && n == uintptr(len(buf))
}
