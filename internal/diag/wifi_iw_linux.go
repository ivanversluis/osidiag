//go:build linux

package diag

import (
	"context"
	"encoding/hex"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Linux Wireless Extensions are sparse on modern nl80211 adapters. The
// optional iw command can query existing association/station state without
// initiating a scan or changing the network. No shell is involved.
var wirelessWidth = regexp.MustCompile(`(?:width:\s*|\b)(20|40|80|160|320)\s*MHz`)

func passiveIW(name string, args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	all := append([]string{"dev", name}, args...)
	out, err := exec.CommandContext(ctx, "iw", all...).Output()
	if err != nil || len(out) > 65536 {
		return nil
	}
	return out
}

func printableSSID(raw string) string {
	for _, r := range raw {
		if !unicode.IsPrint(r) {
			return "hex:" + hex.EncodeToString([]byte(raw))
		}
	}
	return raw
}

func iwFloat(text string) (float64, bool) {
	parts := strings.Fields(text)
	if len(parts) == 0 { return 0, false }
	n, err := strconv.ParseFloat(parts[0], 64)
	return n, err == nil
}

// parseIWLink understands the passive iw(8) station/link format; failures
// mean unknown values, not bad radio state.
func parseIWLink(raw []byte) map[string]any {
	data := map[string]any{}
	connected := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Connected to ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				data["bssid"] = strings.ToLower(fields[2])
				connected = true
			}
			continue
		}
		key, v, ok := strings.Cut(line, ":")
		if !ok { continue }
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "ssid":
			data["ssid"] = printableSSID(v)
		case "freq":
			freqFields := strings.Fields(v)
			if len(freqFields) == 0 { continue }
			if n, err := strconv.Atoi(freqFields[0]); err == nil && n > 0 {
				data["frequency_mhz"] = n
				data["band"] = wifiFrequencyBand(n)
			}
		case "signal":
			if n, ok := iwFloat(v); ok && n >= -110 && n <= -20 {
				data["signal_dbm"] = int(n)
			}
		case "rx bitrate", "tx bitrate":
			if n, ok := iwFloat(v); ok && n > 0 {
				field := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), " ", "_") + "_mbps"
				data[field] = n
			}
			if width := wirelessWidth.FindStringSubmatch(v); len(width) > 1 {
				if w, err := strconv.Atoi(width[1]); err == nil { data["channel_width_mhz"] = w }
			}
			standard := strings.ToUpper(v)
			switch {
			case strings.Contains(standard, "EHT-"):
				data["phy_standard"] = "802.11be"
			case strings.Contains(standard, "HE-"):
				data["phy_standard"] = "802.11ax"
			case strings.Contains(standard, "VHT-"):
				data["phy_standard"] = "802.11ac"
			case strings.Contains(standard, "HT-"):
				data["phy_standard"] = "802.11n"
			}
		}
	}
	data["associated"] = connected
	return data
}

func wifiFrequencyBand(mhz int) string {
	switch {
	case mhz >= 2400 && mhz < 2500: return "2.4 GHz"
	case mhz >= 4900 && mhz < 5925: return "5 GHz"
	case mhz >= 5925 && mhz < 7125: return "6 GHz"
	default: return "unknown"
	}
}

func parseIWInfo(raw []byte) map[string]any {
	data := map[string]any{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "channel ") { continue }
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if channel, err := strconv.Atoi(fields[1]); err == nil { data["channel"] = channel }
		}
		if match := wirelessWidth.FindStringSubmatch(line); len(match) > 1 {
			if width, err := strconv.Atoi(match[1]); err == nil { data["channel_width_mhz"] = width }
		}
		break
	}
	return data
}

func parseIWStation(raw []byte) map[string]any {
	data := map[string]any{}
	nStations := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Station ") { nStations++ }
	}
	// A client should have exactly one associated AP. Avoid attributing
	// multi-client AP mode totals to a single station.
	if nStations != 1 { return data }
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok { continue }
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if !strings.HasPrefix(key, "tx retries") && !strings.HasPrefix(key, "tx failed") &&
			!strings.HasPrefix(key, "beacon loss") && key != "connected time" && key != "tx packets" { continue }
		if key=="connected time" {
			if n,ok:=iwFloat(value);ok && n>=0 {data["connected_seconds"]=n}
			continue
		}
		parts:=strings.Fields(value)
		if len(parts)==0 {continue}
		n,err:=strconv.ParseUint(parts[0],10,64)
		if err!=nil {continue}
		switch key {
		case "tx packets": data["tx_packets_total"] = n
		case "tx retries": data["tx_retries_total"] = n
		case "tx failed": data["tx_failed_total"] = n
		case "beacon loss": data["beacon_loss_total"] = n
		}
	}
	return data
}

func wifiIWDetails(name string) map[string]any {
	data := map[string]any{}
	link := passiveIW(name,"link")
	if len(link) == 0 {
		data["iw_note"] = "iw unavailable or station query denied; nl80211 metadata is unknown (no scan performed)"
		return data
	}
	for k, v := range parseIWLink(link) { data[k] = v }
	for k, v := range parseIWInfo(passiveIW(name,"info")) { data[k] = v }
	for k, v := range parseIWStation(passiveIW(name,"station","dump")) { data[k] = v }
	if raw := passiveIW(name,"get","power_save"); len(raw) > 0 {
		text := strings.ToLower(string(raw))
		if strings.Contains(text,"power save: on") { data["power_save"] = "on" }
		if strings.Contains(text,"power save: off") { data["power_save"] = "off" }
	}
	if _, ok := data["channel"]; !ok { data["channel"] = "unknown" }
	if _, ok := data["channel_width_mhz"]; !ok { data["channel_width_mhz"] = "unknown" }
	if _, ok := data["phy_standard"]; !ok { data["phy_standard"] = "unknown" }
	data["security"] = "unknown (passive association does not disclose full cipher)"
	data["neighbor_aps"] = "unknown (active scan intentionally not performed)"
	data["roaming_history"] = "unknown (requires repeated observations)"
	return data
}
