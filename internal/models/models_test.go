package models

import (
	"testing"
)

func TestValueKnown(t *testing.T) {
	v := Known("C:\\Windows\\System32\\svchost.exe")
	got, ok := v.Get()
	if !ok || got != "C:\\Windows\\System32\\svchost.exe" || !v.IsKnown() || v.Reason() != "" {
		t.Fatalf("Known value: got %q ok=%v reason=%q", got, ok, v.Reason())
	}
}

func TestValueUnavailableNeverCarriesData(t *testing.T) {
	v := Unavailable[uint32]("access denied")
	got, ok := v.Get()
	if ok || got != 0 || v.IsKnown() {
		t.Fatalf("Unavailable value must carry no data: got %d ok=%v", got, ok)
	}
	if v.Reason() != "access denied" {
		t.Fatalf("reason = %q", v.Reason())
	}
	if r := Unavailable[string]("").Reason(); r != "no reason recorded" {
		t.Fatalf("empty reason = %q", r)
	}
}

func TestValueZeroIsNotCollected(t *testing.T) {
	var v Value[string]
	if v.IsKnown() || v.Reason() != "not collected" {
		t.Fatalf("zero Value: known=%v reason=%q", v.IsKnown(), v.Reason())
	}
}

func TestSeverityOrderAndText(t *testing.T) {
	order := []Severity{SeverityNone, SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh}
	for i := 1; i < len(order); i++ {
		if order[i-1] >= order[i] {
			t.Fatalf("%v should be below %v", order[i-1], order[i])
		}
	}
	for _, s := range order {
		b, err := s.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var back Severity
		if err := back.UnmarshalText(b); err != nil || back != s {
			t.Fatalf("round trip %v: got %v err=%v", s, back, err)
		}
	}
	if _, err := Severity(99).MarshalText(); err == nil {
		t.Fatal("invalid severity marshaled")
	}
	var s Severity
	if err := s.UnmarshalText([]byte("Critical")); err == nil {
		t.Fatal("unknown severity name accepted")
	}
}
