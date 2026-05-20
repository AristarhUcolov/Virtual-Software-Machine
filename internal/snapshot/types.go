// Package snapshot captures the state of the file system and the Windows
// registry before and after a sandbox run, and computes the difference.
//
// Пакет snapshot фиксирует состояние файловой системы и реестра Windows
// до и после запуска в песочнице и вычисляет разницу.
package snapshot

import "time"

// ChangeType classifies a detected difference.
// ChangeType классифицирует обнаружённое изменение.
type ChangeType string

const (
	Added    ChangeType = "added"
	Modified ChangeType = "modified"
	Deleted  ChangeType = "deleted"
)

// FileEntry is a single file recorded in a file-system snapshot.
// FileEntry — один файл, зафиксированный в снимке файловой системы.
type FileEntry struct {
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	Mode    string    `json:"mode"`
	SHA256  string    `json:"sha256,omitempty"`
}

// FSSnapshot is the set of files found under a list of roots at a moment.
// FSSnapshot — множество файлов под заданными корнями в момент снимка.
type FSSnapshot struct {
	Roots   []string             `json:"roots"`
	Files   map[string]FileEntry `json:"-"` // keyed by lower-cased path
	TakenAt time.Time            `json:"taken_at"`
}

// FSChange is one file-system difference between two snapshots.
// FSChange — одно различие файловой системы между двумя снимками.
type FSChange struct {
	Type   ChangeType `json:"type"`
	Path   string     `json:"path"`
	Before *FileEntry `json:"before,omitempty"`
	After  *FileEntry `json:"after,omitempty"`
}

// RegValue is one registry value (name, type and stringified data).
// RegValue — одно значение реестра (имя, тип и данные в виде строки).
type RegValue struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
}

// RegSnapshot is the set of registry values found under a list of roots.
// RegSnapshot — множество значений реестра под заданными корнями.
type RegSnapshot struct {
	Roots   []string                       `json:"roots"`
	Keys    map[string]map[string]RegValue `json:"-"` // keyPath -> valueName -> value
	TakenAt time.Time                      `json:"taken_at"`
}

// RegChange is one registry difference between two snapshots.
// RegChange — одно различие реестра между двумя снимками.
type RegChange struct {
	Type      ChangeType `json:"type"`
	KeyPath   string     `json:"key_path"`
	ValueName string     `json:"value_name"`
	Before    *RegValue  `json:"before,omitempty"`
	After     *RegValue  `json:"after,omitempty"`
}
