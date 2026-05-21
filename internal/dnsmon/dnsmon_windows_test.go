package dnsmon

import "testing"

// TestSnapshotDoesNotCrash exercises the real DnsGetCacheDataTable walk on the
// host. It runs in CI on a clean Windows machine, so a broken syscall or a bad
// struct layout would turn CI red.
func TestSnapshotDoesNotCrash(t *testing.T) {
	names := Snapshot()
	if names == nil {
		t.Fatal("Snapshot must return a non-nil map")
	}
	for n := range names {
		if n == "" {
			t.Error("Snapshot must not contain empty names")
		}
	}
	t.Logf("DNS cache holds %d names", len(names))
}

func TestDiff(t *testing.T) {
	before := map[string]bool{"example.com": true, "old.local": true}
	after := map[string]bool{"example.com": true, "evil-c2.net": true, "cdn.test": true}

	got := Diff(before, after)
	if len(got) != 2 {
		t.Fatalf("Diff = %v, want 2 new names", got)
	}
	// Diff is sorted.
	if got[0] != "cdn.test" || got[1] != "evil-c2.net" {
		t.Errorf("Diff = %v, want [cdn.test evil-c2.net]", got)
	}
}

func TestDiffEmpty(t *testing.T) {
	if got := Diff(map[string]bool{"a": true}, map[string]bool{"a": true}); len(got) != 0 {
		t.Errorf("Diff with no new names = %v, want empty", got)
	}
}

func TestDecodeUTF16Z(t *testing.T) {
	// "ab" then a NUL, then trailing garbage that must be ignored.
	b := []byte{'a', 0, 'b', 0, 0, 0, 'x', 0}
	if got := decodeUTF16Z(b); got != "ab" {
		t.Errorf("decodeUTF16Z = %q, want ab", got)
	}
}
