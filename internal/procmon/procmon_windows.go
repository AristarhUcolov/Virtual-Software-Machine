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
			PID:       int(pid),
			Image:     imageName(pid),
			IsRoot:    pid == m.rootPID,
			FirstSeen: now,
			LastSeen:  now,
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
