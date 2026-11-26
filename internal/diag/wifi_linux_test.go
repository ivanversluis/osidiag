//go:build linux

package diag

import "testing"

func TestWiFiWirelessExtensionParsing(t *testing.T) {
	sample := []byte("Inter-| sta-| Quality        | Discarded packets               | Missed | WE\n" +
		" face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n" +
		"wlan0: 0000   67.  -58.  -97.       0      0      0      0      0        0\n")
	m, found := parseWireless(sample, "wlan0")
	if !found || !m.HasSignal || m.SignalDBM != -58 || m.NoiseDBM != -97 || m.Quality != 67 {
		t.Fatalf("unexpected parsed wireless metrics: %+v found=%v", m, found)
	}
	if _, found := parseWireless(sample, "eth0"); found {
		t.Fatal("Ethernet falsely detected as Wi-Fi")
	}
}
func TestWiFiUnknownSignal(t *testing.T) {
	data := []byte("wlan0: 0000 70.  182.  -256.  0 0 0\n")
	m, found := parseWireless(data, "wlan0")
	if !found || m.HasSignal {
		t.Fatalf("invalid raw signal treated as dBm: %+v", m)
	}
}
func TestWiFiSignalStoplights(t *testing.T) {
	for _, tc := range []struct {
		dbm    int
		name   string
		status Status
	}{
		{-43, "good", OK}, {-67, "good", OK}, {-68, "fair", Warn}, {-76, "fair", Warn}, {-77, "poor", Warn},
	} {
		name, status := wifiQuality(tc.dbm)
		if name != tc.name || status != tc.status {
			t.Errorf("%d -> %s %s", tc.dbm, name, status)
		}
	}
}
