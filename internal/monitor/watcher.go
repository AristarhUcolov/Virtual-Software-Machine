// Package monitor records file-system activity in real time while the
// sandboxed process runs, producing a chronological event timeline that
// complements the before/after snapshot diff.
//
// Пакет monitor фиксирует активность файловой системы в реальном времени
// во время работы процесса в песочнице, формируя хронологию событий,
// которая дополняет снимок «до/после».
//
// On Windows fsnotify uses one handle per watched directory, so the watcher
// is pointed at the (small) sandbox tree only; the broad system roots are
// covered by the snapshot diff instead.
package monitor

import (
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	maxEvents      = 100000 // safety cap on the timeline length
	maxWatchedDirs = 8192   // safety cap on watched directory handles
)

// Event is one observed file-system operation.
// Event — одна наблюдённая операция файловой системы.
type Event struct {
	Time time.Time `json:"time"`
	Op   string    `json:"op"`
	Path string    `json:"path"`
}

// Watcher collects file-system events under a set of roots.
// Watcher собирает события файловой системы под набором корней.
type Watcher struct {
	w     *fsnotify.Watcher
	mu    sync.Mutex
	events []Event
	done  chan struct{}
	addCh chan string
	wg    sync.WaitGroup

	watched int // number of directories currently watched
}

// Start begins watching every root (recursively) and returns a running
// Watcher. The event-draining goroutine is launched before any directory is
// registered, which avoids a deadlock inside fsnotify.
//
// Start начинает наблюдение за каждым корнем (рекурсивно). Горутина чтения
// событий запускается до регистрации каталогов — это исключает дедлок fsnotify.
func Start(roots []string) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	wt := &Watcher{
		w:     fw,
		done:  make(chan struct{}),
		addCh: make(chan string, 8192),
	}
	wt.wg.Add(2)
	go wt.eventLoop()
	go wt.addLoop()
	for _, root := range roots {
		wt.enqueueRecursive(root)
	}
	return wt, nil
}

// enqueueRecursive registers root and all of its existing subdirectories,
// blocking until each is queued so none are dropped at start-up.
func (wt *Watcher) enqueueRecursive(root string) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			select {
			case wt.addCh <- path:
			case <-wt.done:
				return filepath.SkipAll
			}
		}
		return nil
	})
}

// enqueue offers a directory for watching without ever blocking the caller —
// used for directories created while the target runs.
func (wt *Watcher) enqueue(path string) {
	select {
	case wt.addCh <- path:
	default: // queue full — drop; the snapshot diff still covers this path
	}
}

// addLoop performs the actual fsnotify.Add calls in a goroutine separate from
// eventLoop, so an Add never blocks the event drain (and vice versa).
func (wt *Watcher) addLoop() {
	defer wt.wg.Done()
	for {
		select {
		case <-wt.done:
			return
		case p := <-wt.addCh:
			if wt.watched >= maxWatchedDirs {
				continue
			}
			if err := wt.w.Add(p); err == nil {
				wt.watched++
			}
		}
	}
}

// eventLoop drains fsnotify events and records them on the timeline.
func (wt *Watcher) eventLoop() {
	defer wt.wg.Done()
	for {
		select {
		case <-wt.done:
			return
		case ev, ok := <-wt.w.Events:
			if !ok {
				return
			}
			wt.record(ev)
		case _, ok := <-wt.w.Errors:
			if !ok {
				return
			}
		}
	}
}

func (wt *Watcher) record(ev fsnotify.Event) {
	// Newly created directories are queued for watching so nested activity
	// is captured too. // Новые каталоги ставим в очередь на наблюдение.
	if ev.Op.Has(fsnotify.Create) {
		if isDir, err := filepathStat(ev.Name); err == nil && isDir {
			wt.enqueue(ev.Name)
		}
	}
	wt.mu.Lock()
	if len(wt.events) < maxEvents {
		wt.events = append(wt.events, Event{
			Time: time.Now(),
			Op:   ev.Op.String(),
			Path: ev.Name,
		})
	}
	wt.mu.Unlock()
}

// Stop ends watching and returns the collected timeline.
// Stop завершает наблюдение и возвращает собранную хронологию.
func (wt *Watcher) Stop() []Event {
	close(wt.done)
	_ = wt.w.Close()
	wt.wg.Wait()
	wt.mu.Lock()
	defer wt.mu.Unlock()
	out := make([]Event, len(wt.events))
	copy(out, wt.events)
	return out
}

// Count returns the number of events collected so far (thread-safe).
// Count возвращает число уже собранных событий (потокобезопасно).
func (wt *Watcher) Count() int {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	return len(wt.events)
}
