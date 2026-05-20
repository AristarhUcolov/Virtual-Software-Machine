package snapshot

import (
	"testing"
	"time"
)

func TestDiffFS(t *testing.T) {
	t0 := time.Now()
	before := &FSSnapshot{Files: map[string]FileEntry{
		`c:\a`: {Path: `C:\a`, Size: 10, ModTime: t0},
		`c:\b`: {Path: `C:\b`, Size: 20, ModTime: t0},
	}}
	after := &FSSnapshot{Files: map[string]FileEntry{
		`c:\a`: {Path: `C:\a`, Size: 10, ModTime: t0}, // unchanged
		`c:\b`: {Path: `C:\b`, Size: 99, ModTime: t0}, // modified (size)
		`c:\c`: {Path: `C:\c`, Size: 5, ModTime: t0},  // added
	}}

	got := map[string]ChangeType{}
	for _, c := range DiffFS(before, after, 0) {
		got[c.Path] = c.Type
	}
	if _, ok := got[`C:\a`]; ok {
		t.Error("unchanged file A must not appear in the diff")
	}
	if got[`C:\b`] != Modified {
		t.Errorf("file B: %q, want modified", got[`C:\b`])
	}
	if got[`C:\c`] != Added {
		t.Errorf("file C: %q, want added", got[`C:\c`])
	}
}

func TestDiffFSDetectsDeletion(t *testing.T) {
	before := &FSSnapshot{Files: map[string]FileEntry{`c:\x`: {Path: `C:\x`, Size: 1}}}
	after := &FSSnapshot{Files: map[string]FileEntry{}}

	changes := DiffFS(before, after, 0)
	if len(changes) != 1 || changes[0].Type != Deleted {
		t.Fatalf("expected exactly one Deleted change, got %+v", changes)
	}
}

func TestDiffFSModTimeChange(t *testing.T) {
	t0 := time.Now()
	before := &FSSnapshot{Files: map[string]FileEntry{`c:\f`: {Path: `C:\f`, Size: 8, ModTime: t0}}}
	after := &FSSnapshot{Files: map[string]FileEntry{`c:\f`: {Path: `C:\f`, Size: 8, ModTime: t0.Add(time.Hour)}}}

	changes := DiffFS(before, after, 0)
	if len(changes) != 1 || changes[0].Type != Modified {
		t.Fatalf("a mod-time change must be detected as Modified, got %+v", changes)
	}
}
