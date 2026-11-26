package diag

import (
	"math"
	"testing"
	"time"
)

func TestOfficeBSSGroupingAndDedup(t *testing.T) {
	b := []WiFiBSS{
		{SSID: "Example-Office", BSSID: "aa:aa:aa:aa:aa:01", RSSIDBM: -76, Channel: 36},
		{SSID: "Example-Office", BSSID: "AA:AA:AA:AA:AA:01", RSSIDBM: -50, Channel: 36},
		{SSID: "Example-Office", BSSID: "aa:aa:aa:aa:aa:02", RSSIDBM: -62, Channel: 40},
		{SSID: "Guest", BSSID: "bb:bb:bb:bb:bb:01", RSSIDBM: -70},
	}
	groups, total := compactWiFiGroups(b, 2)
	if total != 3 || len(groups) != 2 || groups[0].SSID != "Example-Office" || groups[0].Count != 2 ||
		groups[0].Radios[0].RSSIDBM != -50 || len(groups[1].Radios) != 0 {
		t.Fatalf("incorrect SSID groups: %+v total=%d", groups, total)
	}
}

func TestBSSLoadIERejectsTruncatedAndParses(t *testing.T) {
	for _, raw := range [][]byte{{11, 5, 1, 2}, {0, 5, 1}, {11, 4, 1, 2, 3, 4}} {
		if load, count := parseBSSLoadIE(raw); load != nil || count != nil {
			t.Fatalf("accepted malformed BSS IE: %v %v", load, count)
		}
	}
	load, count := parseBSSLoadIE([]byte{0, 1, 99, 11, 5, 2, 0, 204, 0, 0})
	if load == nil || count == nil || *count != 2 || math.Abs(*load-80) > 0.01 {
		t.Fatalf("BSS Load IE incorrect: %v %v", load, count)
	}
}

func TestWiFiChannelAndRSSI(t *testing.T) {
	for _, tc := range []struct{ f, want int }{{2412, 1}, {2484, 14}, {5180, 36}, {5975, 5}, {5935, 2}, {999, 0}} {
		if got := wifiFrequencyChannel(tc.f); got != tc.want {
			t.Errorf("freq %d gives channel %d", tc.f, got)
		}
	}
	for _, tc := range []struct {
		dbm  int
		want Status
	}{{-50, OK}, {-67, OK}, {-68, Warn}, {-75, Warn}, {-76, Fail}} {
		if got := wifiRSSICheck(tc.dbm, true).Status; got != tc.want {
			t.Errorf("%d: %s, want %s", tc.dbm, got, tc.want)
		}
	}
	if wifiRSSICheck(0, false).Status != Unknown {
		t.Fatal("invented RSSI")
	}
}

func TestOfficeRFStickyCongestionAndBand(t *testing.T) {
	util := 75.0
	current := WiFiBSS{SSID: "Office", BSSID: "00:00:00:00:00:01", RSSIDBM: -73, Band: "2.4 GHz", Channel: 6,
		ChannelUtilPercent: &util, PHY: "802.11n"}
	neighbors := []WiFiBSS{
		current,
		{SSID: "Office", BSSID: "00:00:00:00:00:02", RSSIDBM: -49, Band: "5 GHz", Channel: 36, PHY: "802.11ax"},
		{SSID: "Guest", BSSID: "00:00:00:00:00:03", RSSIDBM: -55, Band: "2.4 GHz", Channel: 6},
		{SSID: "Guest", BSSID: "00:00:00:00:00:04", RSSIDBM: -61, Band: "2.4 GHz", Channel: 6},
		{SSID: "Guest", BSSID: "00:00:00:00:00:05", RSSIDBM: -65, Band: "2.4 GHz", Channel: 6},
		{SSID: "Guest", BSSID: "00:00:00:00:00:05", RSSIDBM: -65, Band: "2.4 GHz", Channel: 6},
	}
	fields, checks := officeWiFiAssessment(current, neighbors, nil, 144, 72, 100)
	if fields["sticky_gain_db"] != 24 || fields["cochannel_bssids_above_minus80"] != 4 {
		t.Fatalf("sticky or congestion evidence wrong: %#v", fields)
	}
	want := map[string]Status{"wifi_rssi": Warn, "wifi_snr": Unknown, "wifi_phy_rate": Warn,
		"wifi_cochannel": Warn, "wifi_channel_utilization": Warn, "wifi_sticky_client": Warn,
		"wifi_band_steering": Warn, "wifi_phy_generation": Warn}
	for _, c := range checks {
		if v, ok := want[c.Name]; ok {
			if v != c.Status {
				t.Errorf("%s=%s expected %s", c.Name, c.Status, v)
			}
			delete(want, c.Name)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing checks: %v", want)
	}
}

func TestOfficeUnknownWithoutCache(t *testing.T) {
	current := WiFiBSS{SSID: "Office", BSSID: "aa", RSSIDBM: -65, Band: "5 GHz", Channel: 36}
	_, checks := officeWiFiAssessment(current, nil, nil, 0, 0, 0)
	for _, c := range checks {
		if c.Name == "wifi_sticky_client" && c.Status != Unknown {
			t.Fatal("empty scan cache cannot prove no sticky client")
		}
		if c.Name == "wifi_cochannel" && c.Status != Unknown {
			t.Fatal("empty scan cache cannot prove no congestion")
		}
	}
}

func TestStationRetryRateAndReset(t *testing.T) {
	a := WiFiStationCounters{TxPackets: 100, TxRetries: 60, TxFailed: 3, BeaconLoss: 1,
		HasPackets: true, HasRetries: true, HasFailed: true, HasBeacons: true}
	b := WiFiStationCounters{TxPackets: 200, TxRetries: 76, TxFailed: 3, BeaconLoss: 2,
		HasPackets: true, HasRetries: true, HasFailed: true, HasBeacons: true}
	fields, checks := assessStationCounters(a, b, 15*time.Second)
	if fields["tx_retries_delta"] != uint64(16) || fields["retry_attempts_per_tx_packet"].(float64) < 0.159 {
		t.Fatalf("bad delta: %v", fields)
	}
	for _, c := range checks {
		if (c.Name == "wifi_tx_retry_ratio" || c.Name == "wifi_beacon_loss") && c.Status != Warn {
			t.Fatalf("missing warning %+v", c)
		}
	}
	b.TxRetries = 0
	_, checks = assessStationCounters(a, b, time.Second)
	if checks[0].Status != Unknown {
		t.Fatalf("counter reset should be unknown %+v", checks)
	}
}

func TestOfficeRoamTransitions(t *testing.T) {
	_, checks := assessWiFiObservations([]WiFiObservation{
		{Connected: true, BSSID: "aa"}, {Connected: true, BSSID: "bb"}, {Connected: true, BSSID: "cc"},
	})
	if checks[0].Status != Warn {
		t.Fatalf("frequent roams should warn: %+v", checks)
	}
	_, checks = assessWiFiObservations(nil)
	if checks[0].Status != Unknown {
		t.Fatal("unsampled roam inferred")
	}
}
