// Package regmon watches a curated set of Windows autostart registry keys in
// real time. Unlike the before/after registry diff, it timestamps the moment
// a key changes — so it also catches transient writes that a sample creates
// and then removes before the post-run snapshot is taken.
//
// Пакет regmon следит за набором ключей автозапуска Windows в реальном
// времени. В отличие от снимка «до/после», он фиксирует момент изменения
// ключа — и поэтому ловит даже временные записи, которые сэмпл создаёт и
// удаляет до финального снимка.
package regmon

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"vsm/internal/monitor"
)

const (
	regNotifyChangeName    = 0x00000001
	regNotifyChangeLastSet = 0x00000004
	maxRegEvents           = 10000
)

var (
	modadvapi32              = windows.NewLazySystemDLL("advapi32.dll")
	procRegNotifyChangeValue = modadvapi32.NewProc("RegNotifyChangeKeyValue")
)

// Watcher watches several registry keys, one goroutine per key.
// Watcher следит за несколькими ключами реестра, по горутине на ключ.
type Watcher struct {
	done   windows.Handle // manual-reset event signalling shutdown
	wg     sync.WaitGroup
	mu     sync.Mutex
	events []monitor.Event
	keys   []registry.Key
}

// Start opens every root and begins watching it. Keys that cannot be opened
// (missing or access denied) are silently skipped.
//
// Start открывает каждый корень и начинает слежение. Ключи, которые открыть
// не удалось (отсутствуют или нет доступа), молча пропускаются.
func Start(roots []string) (*Watcher, error) {
	done, err := windows.CreateEvent(nil, 1, 0, nil) // manual-reset, non-signalled
	if err != nil {
		return nil, err
	}
	w := &Watcher{done: done}
	for _, root := range roots {
		hive, sub, ok := parseRoot(root)
		if !ok {
			continue
		}
		k, err := registry.OpenKey(hive, sub, registry.READ)
		if err != nil {
			continue
		}
		w.keys = append(w.keys, k)
		w.wg.Add(1)
		go w.watch(k, root)
	}
	return w, nil
}

// watch arms RegNotifyChangeKeyValue, waits for either a change or shutdown,
// records the change and re-arms.
func (w *Watcher) watch(key registry.Key, label string) {
	defer w.wg.Done()
	change, err := windows.CreateEvent(nil, 0, 0, nil) // auto-reset
	if err != nil {
		return
	}
	defer windows.CloseHandle(change)

	handles := []windows.Handle{w.done, change}
	for {
		r1, _, _ := procRegNotifyChangeValue.Call(
			uintptr(key),
			1, // bWatchSubtree
			uintptr(regNotifyChangeName|regNotifyChangeLastSet),
			uintptr(change),
			1, // fAsynchronous
		)
		if r1 != 0 { // non-zero LSTATUS — cannot watch this key
			return
		}
		ev, err := windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
		if err != nil {
			return
		}
		if ev == 0 { // w.done signalled — shut down
			return
		}
		w.record(label)
	}
}

func (w *Watcher) record(keyPath string) {
	w.mu.Lock()
	if len(w.events) < maxRegEvents {
		w.events = append(w.events, monitor.Event{
			Time: time.Now(),
			Op:   "REG-CHANGED",
			Path: keyPath,
		})
	}
	w.mu.Unlock()
}

// Stop ends watching and returns the collected registry events.
// Stop завершает слежение и возвращает собранные события реестра.
func (w *Watcher) Stop() []monitor.Event {
	windows.SetEvent(w.done)
	w.wg.Wait()
	for _, k := range w.keys {
		k.Close()
	}
	windows.CloseHandle(w.done)
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]monitor.Event, len(w.events))
	copy(out, w.events)
	return out
}

// parseRoot splits "HKCU\Sub\Path" into a predefined key and the sub-path.
func parseRoot(root string) (registry.Key, string, bool) {
	parts := strings.SplitN(root, `\`, 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	switch strings.ToUpper(parts[0]) {
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, parts[1], true
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, parts[1], true
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, parts[1], true
	case "HKU", "HKEY_USERS":
		return registry.USERS, parts[1], true
	default:
		return 0, "", false
	}
}
