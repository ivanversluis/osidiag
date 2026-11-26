//go:build linux

package diag

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Wi-Fi metrics come from Linux Wireless Extensions' /proc/net/wireless.
// These are best-effort values. Some modern nl80211 drivers do not export them.
type wifiMetrics struct {
	Interface string  `json:"interface"`
	Quality   float64 `json:"link_quality_raw,omitempty"`
	SignalDBM int     `json:"signal_dbm,omitempty"`
	NoiseDBM  int     `json:"noise_dbm,omitempty"`
	HasSignal bool    `json:"-"`
}

func parseWireless(content []byte, interfaceName string) (wifiMetrics, bool) {
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != interfaceName {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 4 {
			return wifiMetrics{Interface: interfaceName}, true
		}
		metric := wifiMetrics{Interface: interfaceName}
		parse := func(s string) (float64, error) {
			return strconv.ParseFloat(strings.TrimSuffix(s, "."), 64)
		}
		if q, err := parse(fields[1]); err == nil {
			metric.Quality = q
		}
		if signal, err := parse(fields[2]); err == nil && signal <= -20 && signal >= -110 {
			metric.SignalDBM = int(signal)
			metric.HasSignal = true
		}
		if noise, err := parse(fields[3]); err == nil && noise <= -20 && noise >= -110 {
			metric.NoiseDBM = int(noise)
		}
		return metric, true
	}
	return wifiMetrics{}, false
}

func hasWirelessSysfs(name string) bool {
	for _, entry := range []string{"wireless", "phy80211"} {
		if _, err := os.Stat(filepath.Join("/sys/class/net", name, entry)); err == nil {
			return true
		}
	}
	return false
}

func readWireless(name string) (wifiMetrics, bool) {
	b, err := os.ReadFile("/proc/net/wireless")
	if err == nil {
		if m, found := parseWireless(b, name); found {
			return m, true
		}
	}
	return wifiMetrics{Interface: name}, hasWirelessSysfs(name)
}

func wifiQuality(rssi int) (string, Status) {
	switch {
	case rssi >= -67:
		return "good", OK
	case rssi >= -76:
		return "fair", Warn
	default:
		return "poor", Warn
	}
}

func wifiDetails(name string) (map[string]any, Status, bool) {
	m, exists := readWireless(name)
	if !exists {
		return nil, Warn, false
	}
	data := map[string]any{"interface": name, "measurement": "Linux /proc/net/wireless",
		"note": "RSSI thresholds are advisory; bandwidth, interference and client load also affect Wi-Fi. No active scan occurs."}
	for k, v := range wifiIWDetails(name) {
		data[k] = v
	}
	if m.Quality != 0 {
		data["link_quality_raw"] = m.Quality
	}
	if m.NoiseDBM != 0 {
		data["noise_dbm"] = m.NoiseDBM
	}
	if !m.HasSignal {
		if signal, ok := data["signal_dbm"].(int); ok {
			quality, status := wifiQuality(signal)
			data["signal_quality"] = quality
			data["measurement"] = "iw nl80211 (passive station link)"
			return data, status, true
		}
		data["signal_quality"] = "unknown"
		data["note"] = "Driver does not expose valid RSSI through Wireless Extensions or passive nl80211; do not infer good/bad from the interface state."
		return data, Warn, true
	}
	nameQuality, status := wifiQuality(m.SignalDBM)
	data["signal_dbm"] = m.SignalDBM
	data["signal_quality"] = nameQuality
	return data, status, true
}

func wsl2() bool {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	return err == nil && (strings.Contains(strings.ToLower(string(b)), "microsoft") || strings.Contains(strings.ToLower(string(b)), "wsl"))
}

func Wireless(o Options) Result {
	name := o.Interface
	if name == "auto" {
		ifaces, err := net.Interfaces()
		if err != nil {
			return result(1, "WiFi", Fail, "cannot enumerate interfaces", nil, err)
		}
		name = ""
		for _, iface := range ifaces {
			_, _, found := wifiDetails(iface.Name)
			if found {
				name = iface.Name
				break
			}
		}
	}
	if name == "" {
		msg := "no Wi-Fi interface visible to Linux"
		if wsl2() {
			msg = "WSL2 cannot inspect the Windows host's Wi-Fi radio; run on native Linux"
		}
		return result(1, "WiFi", Warn, msg, map[string]any{"available": false, "note": msg}, nil)
	}
	details, status, found := wifiDetails(name)
	if !found {
		return result(1, "WiFi", Warn, fmt.Sprintf("%s is not a Linux Wi-Fi interface", name),
			map[string]any{"interface": name, "available": false}, nil)
	}
	survey,checks:=wifiOfficeLinux(name,details,o)
	for k,v:=range survey { details[k]=v }
	details["wifi_office_checks"]=checks
	status=worstWiFiStatus(status,checks)
	if iface,err:=net.InterfaceByName(name);err==nil && len(iface.HardwareAddr)>0 {
		details["client_mac"]=iface.HardwareAddr.String()
		details["client_mac_note"]="Current Wi-Fi interface MAC (may be randomized); search this MAC in Meraki Dashboard."
	}
	summary := fmt.Sprintf("%s: Wi-Fi signal unavailable", name)
	if quality, ok := details["signal_quality"].(string); ok && quality != "unknown" {
		summary = fmt.Sprintf("%s: %d dBm (%s)", name, details["signal_dbm"], quality)
	}
	return result(1, "WiFi", status, summary, details, nil)
}
