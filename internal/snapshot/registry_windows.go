package snapshot

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	maxRegKeys  = 120000 // safety cap on total keys per scan
	maxRegDepth = 40     // safety cap on recursion depth
)

// hiveByName resolves the textual prefix of a registry root to a predefined key.
func hiveByName(name string) (registry.Key, bool) {
	switch strings.ToUpper(name) {
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, true
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, true
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, true
	case "HKU", "HKEY_USERS":
		return registry.USERS, true
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return registry.CURRENT_CONFIG, true
	default:
		return 0, false
	}
}

// ScanRegistry walks each root recursively and records every value found.
// Inaccessible keys are skipped. The scan is bounded by maxRegKeys/maxRegDepth.
//
// ScanRegistry рекурсивно обходит каждый корень и фиксирует все значения.
// Недоступные ключи пропускаются. Обход ограничен maxRegKeys/maxRegDepth.
func ScanRegistry(roots []string) *RegSnapshot {
	snap := &RegSnapshot{
		Roots:   roots,
		Keys:    make(map[string]map[string]RegValue),
		TakenAt: time.Now(),
	}
	for _, root := range roots {
		parts := strings.SplitN(root, `\`, 2)
		if len(parts) != 2 {
			continue
		}
		hive, ok := hiveByName(parts[0])
		if !ok {
			continue
		}
		walkKey(snap, hive, parts[0], parts[1], 0)
	}
	return snap
}

// walkKey opens subPath under hive and recurses. display is the human-readable
// prefix (e.g. "HKCU") used when building canonical key paths in the snapshot.
func walkKey(snap *RegSnapshot, hive registry.Key, display, subPath string, depth int) {
	if depth > maxRegDepth || len(snap.Keys) >= maxRegKeys {
		return
	}
	k, err := registry.OpenKey(hive, subPath, registry.READ)
	if err != nil {
		return // access denied or missing — skip
	}
	defer k.Close()

	full := display + `\` + subPath
	values := map[string]RegValue{}
	names, err := k.ReadValueNames(0)
	if err == nil {
		for _, name := range names {
			rv, ok := readValue(k, name)
			if ok {
				values[strings.ToLower(name)] = rv
			}
		}
	}
	snap.Keys[strings.ToLower(full)] = values

	subs, err := k.ReadSubKeyNames(0)
	if err != nil {
		return
	}
	for _, sub := range subs {
		if len(snap.Keys) >= maxRegKeys {
			return
		}
		walkKey(snap, hive, display, subPath+`\`+sub, depth+1)
	}
}

// readValue reads a single registry value and stringifies its data.
func readValue(k registry.Key, name string) (RegValue, bool) {
	_, valType, err := k.GetValue(name, nil)
	if err != nil && err != registry.ErrShortBuffer {
		return RegValue{}, false
	}
	rv := RegValue{Name: name}
	switch valType {
	case registry.SZ:
		s, _, _ := k.GetStringValue(name)
		rv.Type, rv.Data = "REG_SZ", s
	case registry.EXPAND_SZ:
		s, _, _ := k.GetStringValue(name)
		rv.Type, rv.Data = "REG_EXPAND_SZ", s
	case registry.DWORD:
		n, _, _ := k.GetIntegerValue(name)
		rv.Type, rv.Data = "REG_DWORD", fmt.Sprintf("%d (0x%X)", n, n)
	case registry.QWORD:
		n, _, _ := k.GetIntegerValue(name)
		rv.Type, rv.Data = "REG_QWORD", fmt.Sprintf("%d (0x%X)", n, n)
	case registry.MULTI_SZ:
		ss, _, _ := k.GetStringsValue(name)
		rv.Type, rv.Data = "REG_MULTI_SZ", strings.Join(ss, " | ")
	case registry.BINARY:
		b, _, _ := k.GetBinaryValue(name)
		if len(b) > 256 {
			b = b[:256]
		}
		rv.Type, rv.Data = "REG_BINARY", hex.EncodeToString(b)
	case registry.NONE:
		rv.Type, rv.Data = "REG_NONE", ""
	default:
		rv.Type, rv.Data = fmt.Sprintf("REG_TYPE_%d", valType), ""
	}
	return rv, true
}

// DiffRegistry compares two registry snapshots and returns the ordered list
// of value-level changes.
//
// DiffRegistry сравнивает два снимка реестра и возвращает упорядоченный
// список изменений на уровне значений.
func DiffRegistry(before, after *RegSnapshot) []RegChange {
	var changes []RegChange

	for keyPath, afterVals := range after.Keys {
		beforeVals := before.Keys[keyPath]
		for vName, aVal := range afterVals {
			av := aVal
			bVal, existed := beforeVals[vName]
			switch {
			case !existed:
				changes = append(changes, RegChange{Type: Added, KeyPath: keyPath, ValueName: av.Name, After: &av})
			case bVal.Data != aVal.Data || bVal.Type != aVal.Type:
				bv := bVal
				changes = append(changes, RegChange{Type: Modified, KeyPath: keyPath, ValueName: av.Name, Before: &bv, After: &av})
			}
		}
	}
	for keyPath, beforeVals := range before.Keys {
		afterVals := after.Keys[keyPath]
		for vName, bVal := range beforeVals {
			if _, ok := afterVals[vName]; !ok {
				bv := bVal
				changes = append(changes, RegChange{Type: Deleted, KeyPath: keyPath, ValueName: bv.Name, Before: &bv})
			}
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Type != changes[j].Type {
			return changes[i].Type < changes[j].Type
		}
		if changes[i].KeyPath != changes[j].KeyPath {
			return changes[i].KeyPath < changes[j].KeyPath
		}
		return changes[i].ValueName < changes[j].ValueName
	})
	return changes
}
