package sandbox

import (
	"fmt"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"vsm/internal/config"
)

// Low integrity level SID. A Low-integrity process cannot write to most of the
// user profile or HKCU, which is the core of the user-mode containment.
//
// SID низкого уровня целостности. Процесс с Low-целостностью не может писать
// в большую часть профиля пользователя и в HKCU — основа user-mode изоляции.
const sidLowIntegrity = "S-1-16-4096"

// disableMaxPrivilege strips all privileges from a restricted token.
const disableMaxPrivilege = 0x1

var (
	modadvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = modadvapi32.NewProc("CreateRestrictedToken")
)

// launchResult is the outcome of a contained process run.
// launchResult — итог запуска процесса в изоляции.
type launchResult struct {
	PID           int
	ExitCode      uint32
	IntegrityMode string // "low" or "medium"
	Started       time.Time
	Ended         time.Time
	TimedOut      bool
}

// contained is a running, Job-Object-confined process. Its job handle stays
// valid until close, so monitors (e.g. netmon) can query it during the run.
//
// contained — запущенный процесс, заключённый в Job Object. Хэндл job
// остаётся валидным до close, чтобы мониторы могли опрашивать его во время работы.
type contained struct {
	job     windows.Handle
	process windows.Handle
	pid     uint32
	mode    string
	started time.Time
}

// Job returns the Job Object handle of the contained process tree.
// Job возвращает хэндл Job Object дерева процессов.
func (c *contained) Job() windows.Handle { return c.job }

// PID returns the process id of the main sandboxed process.
// PID возвращает идентификатор главного процесса песочницы.
func (c *contained) PID() uint32 { return c.pid }

// startSandboxed creates a Job Object, then starts targetPath suspended inside
// it (optionally at Low integrity, with a redirected environment), assigns it
// to the job and resumes it. The process is running when this returns.
//
// startSandboxed создаёт Job Object, запускает targetPath в нём в
// приостановленном состоянии и возобновляет. На выходе процесс уже работает.
func startSandboxed(targetPath string, args []string, workDir string, env []string,
	limits config.JobLimits, lowIntegrity bool, log func(string)) (*contained, error) {

	appName, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return nil, fmt.Errorf("target path: %w", err)
	}
	cmdLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{targetPath}, args...)))
	if err != nil {
		return nil, fmt.Errorf("command line: %w", err)
	}
	cwd, err := windows.UTF16PtrFromString(workDir)
	if err != nil {
		return nil, fmt.Errorf("work dir: %w", err)
	}
	envBlock := makeEnvBlock(env)

	job, err := createJob(limits)
	if err != nil {
		return nil, fmt.Errorf("job object: %w", err)
	}

	si := new(windows.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Desktop, _ = windows.UTF16PtrFromString(`winsta0\default`)
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_SHOWNORMAL
	pi := new(windows.ProcessInformation)

	flags := uint32(windows.CREATE_SUSPENDED |
		windows.CREATE_NEW_PROCESS_GROUP |
		windows.CREATE_UNICODE_ENVIRONMENT |
		windows.CREATE_NEW_CONSOLE)

	mode := ""
	if lowIntegrity {
		tok, terr := buildLowIntegrityToken()
		if terr != nil {
			log("low-integrity token unavailable: " + terr.Error() + " — falling back to medium")
		} else {
			cerr := windows.CreateProcessAsUser(tok, appName, cmdLine, nil, nil, false,
				flags, envBlock, cwd, si, pi)
			tok.Close()
			if cerr != nil {
				log("CreateProcessAsUser failed: " + cerr.Error() + " — falling back to medium")
			} else {
				mode = "low"
			}
		}
	}
	if mode == "" {
		if cerr := windows.CreateProcess(appName, cmdLine, nil, nil, false,
			flags, envBlock, cwd, si, pi); cerr != nil {
			windows.CloseHandle(job)
			return nil, fmt.Errorf("create process: %w", cerr)
		}
		mode = "medium"
	}

	// Place the process under our job *before* it executes a single
	// instruction, so every child it spawns is contained too.
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		log("assign to job failed: " + err.Error())
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		log("resume thread failed: " + err.Error())
	}
	windows.CloseHandle(pi.Thread)

	return &contained{
		job:     job,
		process: pi.Process,
		pid:     pi.ProcessId,
		mode:    mode,
		started: time.Now(),
	}, nil
}

// wait blocks until the contained process exits, or kills the whole job tree
// once timeout elapses (timeout <= 0 means wait forever).
//
// wait блокируется до завершения процесса или убивает всё дерево job по
// истечении timeout (timeout <= 0 — ждать бесконечно).
func (c *contained) wait(timeout time.Duration, log func(string)) launchResult {
	res := launchResult{PID: int(c.pid), IntegrityMode: c.mode, Started: c.started}

	waitMs := uint32(windows.INFINITE)
	if timeout > 0 {
		waitMs = uint32(timeout.Milliseconds())
	}
	ev, _ := windows.WaitForSingleObject(c.process, waitMs)
	if ev == uint32(windows.WAIT_TIMEOUT) {
		res.TimedOut = true
		log("timeout reached — terminating job tree")
		_ = windows.TerminateJobObject(c.job, 1)
		_, _ = windows.WaitForSingleObject(c.process, 5000)
	}
	_ = windows.GetExitCodeProcess(c.process, &res.ExitCode)
	res.Ended = time.Now()
	return res
}

// close releases the process and job handles. Closing the job kills any
// process that somehow outlived the wait (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
//
// close освобождает хэндлы процесса и job. Закрытие job убивает любой
// процесс, переживший ожидание.
func (c *contained) close() {
	if c.process != 0 {
		windows.CloseHandle(c.process)
	}
	if c.job != 0 {
		windows.CloseHandle(c.job)
	}
}

// createJob creates a Job Object that kills its whole process tree when the
// handle closes, and applies the configured resource caps.
func createJob(limits config.JobLimits) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if limits.MaxProcesses > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		info.BasicLimitInformation.ActiveProcessLimit = uint32(limits.MaxProcesses)
	}
	if limits.MaxMemoryMB > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		info.ProcessMemoryLimit = uintptr(limits.MaxMemoryMB) * 1024 * 1024
	}
	if _, err := windows.SetInformationJobObject(job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// buildLowIntegrityToken derives a privilege-stripped, Low-integrity primary
// token from the current process token. Such a token is accepted by
// CreateProcessAsUser without any special privileges.
//
// buildLowIntegrityToken создаёт из токена текущего процесса первичный токен
// без привилегий и с Low-целостностью.
func buildLowIntegrityToken() (windows.Token, error) {
	var procTok windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY|
			windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_GROUPS|windows.TOKEN_ADJUST_PRIVILEGES,
		&procTok)
	if err != nil {
		return 0, err
	}
	defer procTok.Close()

	restricted, err := createRestrictedToken(procTok)
	if err != nil {
		return 0, err
	}
	if err := setTokenIntegrity(restricted, sidLowIntegrity); err != nil {
		restricted.Close()
		return 0, err
	}
	return restricted, nil
}

// createRestrictedToken wraps the advapi32 CreateRestrictedToken call,
// dropping every privilege from the new token.
func createRestrictedToken(base windows.Token) (windows.Token, error) {
	var newTok windows.Token
	r1, _, e := procCreateRestrictedToken.Call(
		uintptr(base),
		uintptr(disableMaxPrivilege),
		0, 0, // SIDs to disable
		0, 0, // privileges to delete
		0, 0, // SIDs to restrict
		uintptr(unsafe.Pointer(&newTok)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", e)
	}
	return newTok, nil
}

// setTokenIntegrity lowers the mandatory integrity level of tok to sidStr.
func setTokenIntegrity(tok windows.Token, sidStr string) error {
	sid, err := windows.StringToSid(sidStr)
	if err != nil {
		return err
	}
	tml := windows.Tokenmandatorylabel{}
	tml.Label.Sid = sid
	tml.Label.Attributes = windows.SE_GROUP_INTEGRITY
	return windows.SetTokenInformation(tok, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&tml)), tml.Size())
}

// makeEnvBlock builds a CREATE_UNICODE_ENVIRONMENT block: "K=V\0K=V\0\0".
func makeEnvBlock(env []string) *uint16 {
	var u []uint16
	for _, e := range env {
		if e == "" {
			continue
		}
		u = append(u, utf16.Encode([]rune(e))...)
		u = append(u, 0)
	}
	u = append(u, 0)
	return &u[0]
}
