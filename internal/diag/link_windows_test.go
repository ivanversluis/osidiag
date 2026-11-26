//go:build windows

package diag

import (
	"testing"
	"unsafe"
)

func TestMIBIfRow2NativeLayout(t *testing.T) {
	// These offsets match Windows SDK's 64-bit MIB_IF_ROW2.
	if offset := unsafe.Offsetof(mibIfRow2{}.TxLinkSpeed); offset != 1192 {
		t.Fatalf("wrong TX speed offset: %d", offset)
	}
	if offset := unsafe.Offsetof(mibIfRow2{}.InErrors); offset != 1240 {
		t.Fatalf("wrong RX error offset: %d", offset)
	}
	if size := unsafe.Sizeof(mibIfRow2{}); size != 1352 {
		t.Fatalf("wrong MIB_IF_ROW2 size: %d", size)
	}
}

func TestWindows64BitCounterRates(t *testing.T) {
	before := mibIfRow2{InErrors: 1<<32 + 10, OutErrors: 20, InDiscards: 100}
	after := mibIfRow2{InErrors: 1<<32 + 12, OutErrors: 21, InDiscards: 105}
	a, b := windowsErrorCounters(before), windowsErrorCounters(after)
	if b["rx_errors"] - a["rx_errors"] != 2 || b["rx_dropped"] - a["rx_dropped"] != 5 {
		t.Fatalf("overflow: %v -> %v", a, b)
	}
}

func TestWindowsWiFiSecurityAssessment(t *testing.T) {
	for _, tc := range []struct {
		c wifiConnection
		want Status
	}{
		{wifiConnection{}, Unknown},
		{wifiConnection{SecurityKnown: true, SecurityEnabled: false}, Warn},
		{wifiConnection{SecurityKnown: true, SecurityEnabled: true, Authentication: 7, Cipher: 2}, Warn},
		{wifiConnection{SecurityKnown: true, SecurityEnabled: true, Authentication: 7, Cipher: 4}, OK},
		{wifiConnection{SecurityKnown: true, SecurityEnabled: true, Authentication: 8, Cipher: 4}, OK},
	} {
		_, got := windowsWiFiSecurity(tc.c)
		if got != tc.want {
			t.Errorf("got %s, want %s for %+v", got, tc.want, tc.c)
		}
	}
}
