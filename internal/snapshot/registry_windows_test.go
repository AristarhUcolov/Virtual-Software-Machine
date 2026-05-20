package snapshot

import "testing"

func TestDiffRegistry(t *testing.T) {
	before := &RegSnapshot{Keys: map[string]map[string]RegValue{
		`hkcu\software\test`: {
			"keep":   {Name: "keep", Type: "REG_SZ", Data: "same"},
			"change": {Name: "change", Type: "REG_SZ", Data: "old"},
			"gone":   {Name: "gone", Type: "REG_SZ", Data: "x"},
		},
	}}
	after := &RegSnapshot{Keys: map[string]map[string]RegValue{
		`hkcu\software\test`: {
			"keep":   {Name: "keep", Type: "REG_SZ", Data: "same"},
			"change": {Name: "change", Type: "REG_SZ", Data: "new"},
			"fresh":  {Name: "fresh", Type: "REG_SZ", Data: "y"},
		},
	}}

	got := map[string]ChangeType{}
	for _, c := range DiffRegistry(before, after) {
		got[c.ValueName] = c.Type
	}
	if _, ok := got["keep"]; ok {
		t.Error("unchanged value must not appear in the diff")
	}
	if got["change"] != Modified {
		t.Errorf("value change: %q, want modified", got["change"])
	}
	if got["fresh"] != Added {
		t.Errorf("value fresh: %q, want added", got["fresh"])
	}
	if got["gone"] != Deleted {
		t.Errorf("value gone: %q, want deleted", got["gone"])
	}
}
