package i18n

import "testing"

func TestTReturnsTranslation(t *testing.T) {
	if got := T(RU, "label.yes"); got != "Да" {
		t.Errorf("T(RU, label.yes) = %q, want Да", got)
	}
	if got := T(EN, "label.yes"); got != "Yes" {
		t.Errorf("T(EN, label.yes) = %q, want Yes", got)
	}
}

func TestTUnknownKeyReturnsKey(t *testing.T) {
	if got := T(RU, "no.such.key"); got != "no.such.key" {
		t.Errorf("unknown key: T = %q, want the key itself", got)
	}
}

func TestTFormatsArguments(t *testing.T) {
	if got := T(EN, "msg.fscount", 7); got != "File system changes: 7" {
		t.Errorf("T with arg = %q", got)
	}
}

func TestNormalize(t *testing.T) {
	if Normalize("en") != EN {
		t.Error(`Normalize("en") must be EN`)
	}
	if Normalize("ru") != RU {
		t.Error(`Normalize("ru") must be RU`)
	}
	if Normalize("zz") != RU {
		t.Error("Normalize of an unknown language must default to RU")
	}
}
