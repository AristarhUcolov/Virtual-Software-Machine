package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ScanFS walks every root and records each regular file. Errors on individual
// files or directories are skipped so a partial snapshot is still useful.
//
// ScanFS обходит каждый корень и фиксирует каждый обычный файл. Ошибки на
// отдельных файлах/каталогах пропускаются — частичный снимок тоже полезен.
func ScanFS(roots []string) *FSSnapshot {
	snap := &FSSnapshot{
		Roots:   roots,
		Files:   make(map[string]FileEntry),
		TakenAt: time.Now(),
	}
	for _, root := range roots {
		root = filepath.Clean(root)
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable entry — skip, keep walking
			}
			if d.IsDir() {
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 {
				return nil // do not follow links / reparse points
			}
			info, e := d.Info()
			if e != nil {
				return nil
			}
			snap.Files[strings.ToLower(path)] = FileEntry{
				Path:    path,
				Size:    info.Size(),
				ModTime: info.ModTime(),
				Mode:    info.Mode().String(),
			}
			return nil
		})
	}
	return snap
}

// DiffFS compares two file-system snapshots and returns the ordered list of
// changes. For added and modified files smaller than hashLimitBytes a SHA-256
// digest is computed (handy for malware triage and VirusTotal lookups).
//
// DiffFS сравнивает два снимка файловой системы и возвращает упорядоченный
// список изменений. Для добавленных и изменённых файлов меньше hashLimitBytes
// вычисляется SHA-256 (удобно для триажа вредоносного ПО и проверки в VirusTotal).
func DiffFS(before, after *FSSnapshot, hashLimitBytes int64) []FSChange {
	var changes []FSChange

	for key, a := range after.Files {
		ac := a
		b, existed := before.Files[key]
		switch {
		case !existed:
			ac.SHA256 = hashFile(ac.Path, ac.Size, hashLimitBytes)
			changes = append(changes, FSChange{Type: Added, Path: ac.Path, After: &ac})
		case b.Size != a.Size || !b.ModTime.Equal(a.ModTime):
			bc := b
			ac.SHA256 = hashFile(ac.Path, ac.Size, hashLimitBytes)
			changes = append(changes, FSChange{Type: Modified, Path: ac.Path, Before: &bc, After: &ac})
		}
	}
	for key, b := range before.Files {
		if _, ok := after.Files[key]; !ok {
			bc := b
			changes = append(changes, FSChange{Type: Deleted, Path: bc.Path, Before: &bc})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Type != changes[j].Type {
			return changes[i].Type < changes[j].Type
		}
		return strings.ToLower(changes[i].Path) < strings.ToLower(changes[j].Path)
	})
	return changes
}

// hashFile returns the hex SHA-256 of path, or "" when the file is too large
// or cannot be read.
func hashFile(path string, size, limitBytes int64) string {
	if limitBytes > 0 && size > limitBytes {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HashFile is the exported helper used to fingerprint the analysed target.
// HashFile — экспортируемый помощник для отпечатка анализируемого файла.
func HashFile(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return hashFile(path, info.Size(), 0)
}
