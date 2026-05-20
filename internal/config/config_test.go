package config

import "testing"

func TestDedupRemovesCaseInsensitiveDuplicates(t *testing.T) {
	got := dedup([]string{`C:\X`, `c:\x`, `C:\Y`, "", `C:\Y`})
	if len(got) != 2 {
		t.Fatalf("dedup = %v, want 2 unique entries", got)
	}
}

func TestDefaultPopulatesEssentials(t *testing.T) {
	c := Default("ru")
	if c.Lang != "ru" {
		t.Errorf("Lang = %q, want ru", c.Lang)
	}
	if c.TimeoutSec <= 0 {
		t.Error("default TimeoutSec must be positive")
	}
	if len(c.RegistryRoots) == 0 {
		t.Error("default RegistryRoots must not be empty")
	}
	if len(c.RegWatchRoots) == 0 {
		t.Error("default RegWatchRoots must not be empty")
	}
}

func TestAutorunRegistryRootsAreScoped(t *testing.T) {
	for _, root := range AutorunRegistryRoots() {
		if root == `HKCU\Software` {
			t.Error("autorun roots must stay narrow, not watch a whole hive")
		}
	}
}
