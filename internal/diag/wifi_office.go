package diag

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// WiFiBSS is a single radio (BSSID), not an SSID. Office APs commonly
// advertise the same SSID on many radios. Values absent from a driver remain
// zero/omitted and must not be interpreted as measured zeros.
type WiFiBSS struct {
	SSID               string   `json:"ssid"`
	BSSID              string   `json:"bssid"`
	RSSIDBM            int      `json:"rssi_dbm,omitempty"`
	FrequencyMHz       int      `json:"frequency_mhz,omitempty"`
	Band               string   `json:"band,omitempty"`
	Channel            int      `json:"channel,omitempty"`
	WidthMHz           int      `json:"width_mhz,omitempty"`
	PHY                string   `json:"phy,omitempty"`
	ChannelUtilPercent *float64 `json:"bss_load_channel_util_percent,omitempty"`
	StationCount       *int     `json:"bss_load_station_count,omitempty"`
}

type WiFiSSIDGroup struct {
	SSID    string    `json:"ssid"`
	Count   int       `json:"bssid_count"`
	Radios  []WiFiBSS `json:"radios,omitempty"`
}

type WiFiObservation struct {
	ElapsedMS int64  `json:"elapsed_ms"`
	Connected bool   `json:"connected"`
	BSSID     string `json:"bssid,omitempty"`
}

type WiFiStationCounters struct {
	TxPackets  uint64 `json:"tx_packets"`
	TxRetries  uint64 `json:"tx_retries"`
	TxFailed   uint64 `json:"tx_failed"`
	BeaconLoss uint64 `json:"beacon_loss"`
	HasPackets bool   `json:"-"`
	HasRetries bool   `json:"-"`
	HasFailed  bool   `json:"-"`
	HasBeacons bool   `json:"-"`
}

// compactWiFiGroups groups by SSID, deduplicates APs by BSSID, and limits
// displayed radios without making congestion counts dependent on --limit.
func compactWiFiGroups(radios []WiFiBSS, limit int) ([]WiFiSSIDGroup, int) {
	groups := map[string]map[string]WiFiBSS{}
	for _, b := range radios {
		if b.SSID == "" || b.BSSID == "" {
			continue // hidden SSIDs cannot support same-SSID roaming checks
		}
		key := strings.ToLower(b.BSSID)
		if groups[b.SSID] == nil {
			groups[b.SSID] = map[string]WiFiBSS{}
		}
		old, ok := groups[b.SSID][key]
		if !ok || b.RSSIDBM > old.RSSIDBM {
			groups[b.SSID][key] = b
		}
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]WiFiSSIDGroup, 0, len(names))
	total, remaining := 0, limit
	if remaining < 0 {
		remaining = 0
	}
	for _, name := range names {
		found := make([]WiFiBSS, 0, len(groups[name]))
		for _, b := range groups[name] {
			found = append(found, b)
		}
		sort.Slice(found, func(i, j int) bool {
			if found[i].RSSIDBM == found[j].RSSIDBM {
				return found[i].BSSID < found[j].BSSID
			}
			return found[i].RSSIDBM > found[j].RSSIDBM
		})
		group := WiFiSSIDGroup{SSID: name, Count: len(found)}
		total += group.Count
		n := len(found)
		if n > remaining {
			n = remaining
		}
		group.Radios = append([]WiFiBSS{}, found[:n]...)
		remaining -= n
		out = append(out, group)
	}
	return out, total
}

// parseBSSLoadIE reads IEEE 802.11 BSS Load IE (ID 11). This is not a
// measured airtime survey: the AP may not advertise it and may be stale.
func parseBSSLoadIE(ies []byte) (*float64, *int) {
	for len(ies) >= 2 {
		id, n := ies[0], int(ies[1])
		ies = ies[2:]
		if len(ies) < n {
			return nil, nil
		}
		if id == 11 && n >= 5 {
			stations := int(ies[0]) | int(ies[1])<<8
			load := 100 * float64(ies[2]) / 255
			return &load, &stations
		}
		ies = ies[n:]
	}
	return nil, nil
}

func wifiFrequencyChannel(mhz int) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472 && (mhz-2407)%5 == 0:
		return (mhz-2407)/5
	case mhz == 5935:
		return 2
	case mhz >= 5955 && mhz <= 7115 && (mhz-5950)%5 == 0:
		return (mhz-5950)/5
	case mhz >= 5000 && mhz < 5925 && (mhz-5000)%5 == 0:
		return (mhz-5000)/5
	default:
		return 0
	}
}

func hasWiFiRSSI(b WiFiBSS) bool {
	return b.RSSIDBM >= -110 && b.RSSIDBM <= -20
}

func wifiRSSICheck(dbm int, known bool) LinkCheck {
	if !known {
		return LinkCheck{"wifi_rssi", Unknown, "unknown", "station RSSI or associated BSS cache",
			"Windows connection quality percent is not an RSSI measurement."}
	}
	if dbm < -75 {
		return LinkCheck{"wifi_rssi", Fail, dbm, "station/BSS RSSI dBm",
			"Severely weak RF signal; review AP placement, power and roaming. This is not proof of L1 carrier loss."}
	}
	if dbm < -67 {
		return LinkCheck{"wifi_rssi", Warn, dbm, "station/BSS RSSI dBm",
			"Signal is below the -67 dBm design target; inspect coverage and AP transmit power."}
	}
	return LinkCheck{"wifi_rssi", OK, dbm, "station/BSS RSSI dBm", ""}
}

func officeWiFiAssessment(current WiFiBSS, neighbors []WiFiBSS, noise *int, rxMbps, txMbps, minMbps float64) (map[string]any, []LinkCheck) {
	data := map[string]any{
		"associated_bss": current,
		"ap_cache": "OS scan cache (may be stale; no scan is initiated)",
	}
	checks := []LinkCheck{wifiRSSICheck(current.RSSIDBM, hasWiFiRSSI(current))}
	if noise == nil || !hasWiFiRSSI(current) {
		checks = append(checks, LinkCheck{"wifi_snr", Unknown, "unknown", "driver noise floor",
			"Windows WLAN API does not expose noise floor; Linux driver may omit it."})
	} else {
		snr := current.RSSIDBM - *noise
		data["snr_db"] = snr
		status := OK
		hint := ""
		if snr < 25 {
			status = Warn
			hint = "SNR under 25 dB; inspect co-channel interference and AP channel/power plan."
		}
		checks = append(checks, LinkCheck{"wifi_snr", status, snr, "RSSI - driver noise floor", hint})
	}
	if minMbps <= 0 || rxMbps <= 0 || txMbps <= 0 {
		checks = append(checks, LinkCheck{"wifi_phy_rate", Unknown, map[string]float64{"rx_mbps":rxMbps,"tx_mbps":txMbps},
			"associated station PHY rates", "Specify --min-wifi-mbps to assess negotiated rates; PHY Mbps is not throughput."})
	} else {
		slowest := math.Min(rxMbps, txMbps)
		status, hint := OK, ""
		if slowest < minMbps {
			status = Warn
			hint = fmt.Sprintf("PHY rate below %.0f Mbps; check weak RSSI, minimum bitrate in Meraki RF profile and client capabilities.", minMbps)
		}
		checks = append(checks, LinkCheck{"wifi_phy_rate", status, map[string]float64{"rx_mbps":rxMbps,"tx_mbps":txMbps},
			"associated station PHY rates", hint})
	}
	other := map[string]WiFiBSS{}
	best := WiFiBSS{}
	bestFound := false
	sameChannel := map[string]bool{}
	widerBand := false
	higherPHY := false
	for _, b := range neighbors {
		if b.BSSID == "" || !hasWiFiRSSI(b) {
			continue
		}
		key := strings.ToLower(b.BSSID)
		if old, ok := other[key]; ok && old.RSSIDBM >= b.RSSIDBM {
			continue
		}
		other[key] = b
	}
	for _, b := range other {
		if current.Channel > 0 && b.Channel == current.Channel && b.Band == current.Band && b.RSSIDBM > -80 {
			sameChannel[strings.ToLower(b.BSSID)] = true
		}
		if b.SSID != current.SSID || strings.EqualFold(b.BSSID, current.BSSID) {
			continue
		}
		if !bestFound || b.RSSIDBM > best.RSSIDBM {
			best, bestFound = b, true
		}
		if current.Band == "2.4 GHz" && (b.Band == "5 GHz" || b.Band == "6 GHz") && b.RSSIDBM >= -75 {
			widerBand = true
		}
		if current.PHY == "802.11n" && (b.PHY == "802.11ac" || b.PHY == "802.11ax" || b.PHY == "802.11be") {
			higherPHY = true
		}
	}
	if len(other) == 0 {
		checks = append(checks, LinkCheck{"wifi_ap_neighbors", Unknown, "unknown", "OS BSS cache",
			"No usable BSSID RSSI observations. A scan cache can be empty on Windows without location access."})
	} else {
		data["bssid_count"] = len(other)
	}
	if current.Channel > 0 && len(other) > 0 {
		count := len(sameChannel)
		data["cochannel_bssids_above_minus80"] = count
		status, hint := OK, ""
		if count > 3 {
			status = Warn
			hint = "More than three strong BSSIDs on the channel; review Meraki RF profile, width (80 MHz can be excessive), AP power and channel plan. BSSIDs are not distinct radios."
		}
		checks = append(checks, LinkCheck{"wifi_cochannel", status, count, "BSS cache; unique BSSIDs on channel above -80 dBm", hint})
	} else {
		checks = append(checks, LinkCheck{"wifi_cochannel", Unknown, "unknown", "BSS cache",
			"Current channel or usable neighboring BSSIDs unavailable."})
	}
	if current.ChannelUtilPercent != nil {
		load := *current.ChannelUtilPercent
		status, hint := OK, ""
		if load > 50 {
			status = Warn
			hint = "Associated AP reports over 50% channel utilization (BSS Load IE); review Meraki RF profile and airtime."
		}
		checks = append(checks, LinkCheck{"wifi_channel_utilization", status, math.Round(load*10)/10,
			"Associated AP BSS Load IE (AP-advertised, cached)", hint})
	} else {
		checks = append(checks, LinkCheck{"wifi_channel_utilization", Unknown, "unknown",
			"BSS Load IE", "AP did not advertise BSS Load or cached IEs are unavailable."})
	}
	if bestFound && hasWiFiRSSI(current) {
		gain := best.RSSIDBM - current.RSSIDBM
		if current.RSSIDBM < -70 && gain >= 10 {
			data["sticky_candidate"] = best
			data["sticky_gain_db"] = gain
			checks = append(checks, LinkCheck{"wifi_sticky_client", Warn, fmt.Sprintf("candidate %s +%d dB", best.BSSID, gain),
				"associated BSSID compared with same-SSID BSS cache",
				"Potential sticky client; inspect Meraki 802.11k/v, minimum bitrate, band steering and AP transmit power. Candidate visibility does not ensure it will accept association."})
		} else {
			checks = append(checks, LinkCheck{"wifi_sticky_client", OK, "no stronger candidate meeting thresholds",
				"same-SSID BSS cache", ""})
		}
	} else {
		checks = append(checks, LinkCheck{"wifi_sticky_client", Unknown, "unknown", "same-SSID BSS cache",
			"Need associated BSSID RSSI and at least one other same-SSID BSSID to compare."})
	}
	if current.Band == "" || current.Band == "unknown" {
		checks = append(checks, LinkCheck{"wifi_band_steering", Unknown, "unknown", "connected frequency",
			"Cannot assess band steering without the connected AP band."})
	} else if current.Band != "2.4 GHz" {
		checks = append(checks, LinkCheck{"wifi_band_steering", OK, current.Band, "connected frequency", ""})
	} else if len(other) == 0 {
		checks = append(checks, LinkCheck{"wifi_band_steering", Unknown, current.Band, "same-SSID BSS cache", ""})
	} else if widerBand {
		checks = append(checks, LinkCheck{"wifi_band_steering", Warn, current.Band, "same-SSID BSS cache",
			"Same SSID has usable 5/6 GHz APs. Check client support and Meraki band steering, power and minimum basic rate."})
	} else {
		checks = append(checks, LinkCheck{"wifi_band_steering", OK, current.Band, "same-SSID BSS cache", ""})
	}
	if current.WidthMHz >= 80 && (len(sameChannel)>3 || (current.ChannelUtilPercent!=nil && *current.ChannelUtilPercent>50)) {
		checks=append(checks,LinkCheck{"wifi_channel_width",Warn,current.WidthMHz,"associated AP channel width / RF occupancy",
			"Wide 80/160 MHz channels can amplify contention in dense offices; consider 20/40 MHz in the Meraki RF profile."})
	}
	if higherPHY {
		checks = append(checks, LinkCheck{"wifi_phy_generation", Warn, current.PHY, "neighbor PHY capability",
			"Associated on 802.11n although a same-SSID BSS advertises ac/ax/be; verify station capability before concluding a problem."})
	}
	return data, checks
}

func assessStationCounters(a, b WiFiStationCounters, elapsed time.Duration) (map[string]any, []LinkCheck) {
	data := map[string]any{}
	checks := []LinkCheck{}
	if elapsed <= 0 || !a.HasRetries || !b.HasRetries || !a.HasPackets || !b.HasPackets ||
		b.TxRetries < a.TxRetries || b.TxPackets < a.TxPackets {
		return data, []LinkCheck{{"wifi_tx_retry_ratio", Unknown, "unknown", "nl80211 station counter delta",
			"TX retries and packets must be collected twice on the same association."}}
	}
	retries := b.TxRetries - a.TxRetries
	packets := b.TxPackets - a.TxPackets
	data["tx_retries_delta"] = retries
	data["tx_packets_delta"] = packets
	data["station_sample_seconds"] = elapsed.Seconds()
	if packets > 0 {
		// Retries may exceed packets: this is retries per successfully
		// transmitted packet, not the fraction of retried unique frames.
		ratio := float64(retries) / float64(packets)
		data["retry_attempts_per_tx_packet"] = ratio
		status, hint := OK, ""
		if ratio > 0.15 {
			status = Warn
			hint = "More than 0.15 retries per TX packet: potential RF contention or interference; review channel width, AP power and minimum bitrate. This is not a retried-frame percentage."
		}
		checks = append(checks, LinkCheck{"wifi_tx_retry_ratio", status, math.Round(ratio*1000)/1000,
			"nl80211 delta(tx retries)/delta(tx packets)", hint})
	} else {
		checks = append(checks, LinkCheck{"wifi_tx_retry_ratio", Unknown, "no TX packets in sample",
			"nl80211 station counter delta", ""})
	}
	for _, kind := range []struct{
		name string; has bool; before, after uint64
	}{
		{"wifi_tx_failed", a.HasFailed && b.HasFailed, a.TxFailed, b.TxFailed},
		{"wifi_beacon_loss", a.HasBeacons && b.HasBeacons, a.BeaconLoss, b.BeaconLoss},
	} {
		if !kind.has || kind.after < kind.before {
			checks = append(checks, LinkCheck{kind.name, Unknown, "unknown", "nl80211 counter delta", ""})
			continue
		}
		delta := kind.after - kind.before
		data[kind.name+"_delta"] = delta
		status, hint := OK, ""
		if delta > 0 {
			status, hint = Warn, "Counter increased during observation; inspect RF interference, power, channel and AP health."
		}
		checks = append(checks, LinkCheck{kind.name, status, delta, "nl80211 counter delta", hint})
	}
	return data, checks
}

func assessWiFiObservations(readings []WiFiObservation) (map[string]any, []LinkCheck) {
	fields := map[string]any{"wifi_observations": readings, "disconnect_reason_codes": "unknown (no OS notification subscription)"}
	if len(readings) < 2 {
		return fields, []LinkCheck{{"wifi_roaming", Unknown, "not sampled", "station association snapshots",
			"Use --wifi-sample 15s to observe BSSID changes; does not provide historical deauth reasons."}}
	}
	valid:=0
	for _,s:=range readings {if s.Connected && s.BSSID!="" {valid++}}
	if valid<2 {
		return fields, []LinkCheck{{"wifi_roaming",Unknown,"unknown","station association snapshots",
			"Insufficient valid connected BSSID readings to infer roaming or disconnects."}}
	}
	roams, disconnects := 0, 0
	for i:=1;i<len(readings);i++ {
		if readings[i-1].Connected && !readings[i].Connected { disconnects++ }
		if readings[i-1].Connected && readings[i].Connected &&
			readings[i-1].BSSID != "" && readings[i].BSSID != "" &&
			!strings.EqualFold(readings[i-1].BSSID,readings[i].BSSID) { roams++ }
	}
	fields["bssid_changes_observed"] = roams
	fields["disconnect_transitions_observed"] = disconnects
	status, hint := OK, ""
	if roams > 1 || disconnects > 0 {
		status = Warn
		hint = "Association changed repeatedly or disconnected; inspect roaming/coverage in Meraki event log."
	}
	return fields, []LinkCheck{{"wifi_roaming", status, map[string]int{"bssid_changes":roams,"disconnect_transitions":disconnects},
		"polled association within this observation window (transient events may be missed)", hint}}
}

func worstWiFiStatus(initial Status, checks []LinkCheck) Status {
	s := initial
	for _, c := range checks {
		if c.Status == Fail { return Fail }
		if c.Status == Warn && s == OK { s = Warn }
	}
	return s
}
