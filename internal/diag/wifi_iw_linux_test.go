//go:build linux

package diag

import "testing"

func TestPassiveIWLinkParser(t *testing.T) {
	raw := []byte("Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n" +
		"SSID: Lab-5G\nfreq: 5180\nsignal: -58 dBm\n" +
		"rx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz\n" +
		"tx bitrate: 780.0 MBit/s VHT-MCS 8 80MHz\n")
	got := parseIWLink(raw)
	for k, want := range map[string]any{
		"bssid":"aa:bb:cc:dd:ee:ff", "ssid":"Lab-5G", "signal_dbm":-58,
		"frequency_mhz":5180, "band":"5 GHz", "channel_width_mhz":80,
		"phy_standard":"802.11ac", "associated":true, "rx_bitrate_mbps":866.7,
	} {
		if got[k] != want {t.Errorf("%s=%v; expected %v",k,got[k],want)}
	}
}

func TestPassiveIWStationAndChannel(t *testing.T) {
	info := []byte("Interface wlan0\n  channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz\n")
	m := parseIWInfo(info)
	if m["channel"] != 36 || m["channel_width_mhz"] != 80 { t.Fatalf("channel info: %v",m) }
	s := parseIWStation([]byte("Station aa:bb:cc:dd:ee:ff (on wlan0)\n" +
		"tx retries: 42\ntx failed: 3\nbeacon loss: 2\nconnected time: 132 seconds\n"))
	if s["tx_retries_total"] != uint64(42) || s["tx_failed_total"] != uint64(3) ||
		s["beacon_loss_total"] != uint64(2) || s["connected_seconds"] != float64(132) {
		t.Fatalf("station data: %#v",s)
	}
	empty := parseIWStation([]byte("Station a\nStation b\n"))
	if len(empty) != 0 {t.Fatalf("multi-station AP mode incorrectly reported: %v",empty)}
}

func TestPassiveIWUnknownAndSanitization(t *testing.T) {
	if got := parseIWLink([]byte("Not connected.\n")); got["associated"] != false {
		t.Fatalf("must not invent association: %+v",got)
	}
	if got := printableSSID("evil\x1b[31m"); got != "hex:6576696c1b5b33316d" {
		t.Fatalf("terminal control leaked: %q",got)
	}
	for mhz, want := range map[int]string{2412:"2.4 GHz",5180:"5 GHz",5975:"6 GHz",0:"unknown"} {
		if got := wifiFrequencyBand(mhz); got != want {t.Errorf("%d: %s",mhz,got)}
	}
}
