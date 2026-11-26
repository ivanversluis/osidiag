//go:build linux

package diag

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// linuxLinkProbe deliberately uses passive sysfs reads only. An adapter
// behind a bridge/vSwitch remains the route-selected adapter: we never
// substitute an unrelated physical NIC for it.
type linuxLinkProbe struct{}

func (linuxLinkProbe) Probe(o Options, name string) LinkEvidence {
	base := filepath.Join("/sys/class/net", name)
	e := LinkEvidence{Fields: map[string]any{}, Checks: []LinkCheck{}}
	add := func(c LinkCheck) { e.Checks = append(e.Checks, c) }

	if iface, err := net.InterfaceByName(name); err == nil {
		if iface.Flags&net.FlagUp != 0 {
			add(LinkCheck{"administrative_state", OK, "enabled", "net.Interface.Flags", ""})
		} else {
			add(LinkCheck{"administrative_state", Fail, "disabled", "net.Interface.Flags",
				"Enable the network interface before testing higher layers."})
		}
	} else {
		add(LinkCheck{"administrative_state", Unknown, "unknown", "net.Interface.Flags", err.Error()})
	}
	state := strings.ToLower(sysString(name, "operstate"))
	switch state {
	case "up":
		add(LinkCheck{"operational_state", OK, state, "sysfs operstate", ""})
	case "down", "lowerlayerdown", "notpresent":
		add(LinkCheck{"operational_state", Fail, state, "sysfs operstate", "Check carrier and physical uplink."})
	case "dormant":
		add(LinkCheck{"operational_state", Warn, state, "sysfs operstate", "Interface is waiting for external activation."})
	default:
		add(LinkCheck{"operational_state", Unknown, state, "sysfs operstate", ""})
	}
	carrier := sysString(name, "carrier")
	switch carrier {
	case "1":
		add(LinkCheck{"carrier", OK, "connected", "sysfs carrier", ""})
	case "0":
		add(LinkCheck{"carrier", Fail, "disconnected", "sysfs carrier", "Check the cable, SFP or WLAN association."})
	default:
		add(LinkCheck{"carrier", Unknown, "unknown", "sysfs carrier",
			"Virtual adapters and drivers may not expose physical carrier."})
	}
	has := func(entry string) bool {
		_, err := os.Stat(filepath.Join(base, entry))
		return err == nil
	}
	kind := "unknown"
	switch {
	case has("phy80211") || has("wireless"):
		kind = "wifi"
	case has("device"):
		kind = "ethernet"
	default:
		if p, err := filepath.EvalSymlinks(base); err == nil && strings.Contains(p, "/virtual/net/") {
			kind = "virtual"
		}
	}
	e.Fields["link_kind"] = kind
	switch kind {
	case "virtual":
		add(LinkCheck{"interface_kind", Unknown, kind, "sysfs device topology",
			"Default route uses a virtual interface (for example VPN, WSL2, vSwitch or container). Physical uplink must be diagnosed on its host."})
	case "unknown":
		add(LinkCheck{"interface_kind", Unknown, kind, "sysfs device topology",
			"Physical device metadata is not exposed."})
	default:
		add(LinkCheck{"interface_kind", OK, kind, "sysfs device topology", ""})
	}
	driver := "unknown"
	if target, err := filepath.EvalSymlinks(filepath.Join(base, "device/driver")); err == nil {
		driver = filepath.Base(target)
	}
	e.Fields["driver"] = driver
	if driver == "unknown" {
		add(LinkCheck{"driver", Unknown, driver, "sysfs device/driver",
			"Driver is not exposed, which is expected for many virtual interfaces."})
	} else {
		add(LinkCheck{"driver", OK, driver, "sysfs device/driver", ""})
	}
	speedText := sysString(name, "speed")
	speed, err := strconv.ParseFloat(speedText, 64)
	if err != nil {
		speed = 0
	}
	// PHY bitrate is not the Ethernet port speed. Wi-Fi rates are exposed
	// by the radio probe and should not be compared to an Ethernet minimum.
	if kind == "wifi" {
		add(LinkCheck{"link_speed", Unknown, "not applicable", "sysfs speed",
			"Use associated Wi-Fi TX/RX PHY rates; these are not throughput."})
	} else if kind == "virtual" {
		add(LinkCheck{"link_speed", Unknown, speedText, "sysfs speed",
			"Virtual link speed is not evidence of physical NIC negotiation."})
	} else {
		add(speedCheck(speed, o.MinLinkMbps, "sysfs speed"))
	}
	duplex := strings.ToLower(sysString(name, "duplex"))
	e.Fields["duplex"] = duplex
	switch duplex {
	case "full":
		add(LinkCheck{"duplex", OK, duplex, "sysfs duplex", ""})
	case "half":
		add(LinkCheck{"duplex", Warn, duplex, "sysfs duplex",
			"Half duplex may indicate a negotiation problem; verify peer and NIC settings."})
	default:
		add(LinkCheck{"duplex", Unknown, "unknown", "sysfs duplex", ""})
	}
	flaps, flapErr := readLinuxLinkCounter(base, "carrier_changes")
	if flapErr == nil {
		e.Fields["carrier_changes_total"] = flaps
		add(LinkCheck{"link_flaps", OK, flaps, "sysfs carrier_changes",
			"Cumulative count only; historical flaps alone do not imply current failure."})
	} else {
		add(LinkCheck{"link_flaps", Unknown, "unknown", "sysfs carrier_changes", ""})
	}
	add(LinkCheck{"last_link_change", Unknown, "unknown", "sysfs",
		"Linux sysfs does not expose a portable link-change timestamp."})
	add(LinkCheck{"cable_test", Unknown, "not run", "driver-specific ethtool TDR",
		"TDR can interrupt the link; use an explicit hardware-specific operation."})
	add(LinkCheck{"optical_power", Unknown, "unknown", "driver-specific SFP diagnostics",
		"SFP DOM is not available via portable sysfs fields."})
	if kind == "wifi" {
		add(linuxRadioCheck(name))
	}

	fields := []string{"rx_errors", "tx_errors", "rx_dropped", "tx_dropped", "rx_crc_errors", "rx_frame_errors", "collisions"}
	start, missing := readLinuxStats(base, fields)
	period := o.LinkSample
	if period > 0 && len(start) > 0 {
		begin := time.Now()
		time.Sleep(period)
		end, missingEnd := readLinuxStats(base, fields)
		rates, reset := counterRates(start, end, time.Since(begin))
		missing = append(missing, missingEnd...)
		missing = append(missing, reset...)
		e.Fields["error_rates_per_sec"] = rates
		e.Fields["counter_sample_seconds"] = time.Since(begin).Seconds()
		add(counterCheck(rates, missing, "sysfs statistics (two samples)"))
		if flapErr == nil {
			now, err := readLinuxLinkCounter(base, "carrier_changes")
			if err == nil && now > flaps {
				e.Fields["carrier_changes_during_sample"] = now - flaps
				add(LinkCheck{"recent_link_flaps", Warn, now - flaps, "sysfs carrier_changes delta",
					"Carrier toggled during the sample; check the port, cable, power and NIC."})
			}
		}
	} else {
		add(LinkCheck{"link_errors", Unknown, "not sampled", "sysfs statistics",
			"Use --link-sample 5s to capture per-second error/drop rates."})
	}
	if len(missing) > 0 {
		e.Fields["unavailable_counters"] = uniqueSorted(missing)
	}
	return e
}

func uniqueSorted(items []string) []string {
	m := make(map[string]bool)
	for _, i := range items {
		m[i] = true
	}
	out := make([]string, 0, len(m))
	for i := range m {
		out = append(out, i)
	}
	sort.Strings(out)
	return out
}

func readLinuxLinkCounter(base, field string) (uint64, error) {
	raw, err := os.ReadFile(filepath.Join(base, field))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
}

func readLinuxStats(base string, fields []string) (map[string]uint64, []string) {
	values := map[string]uint64{}
	missing := []string{}
	for _, field := range fields {
		n, err := readLinuxLinkCounter(filepath.Join(base, "statistics"), field)
		if err != nil {
			missing = append(missing, field)
			continue
		}
		values[field] = n
	}
	return values, missing
}

// radioUnderPHY avoids attributing another adapter's rfkill state to the
// selected Wi-Fi interface. A shared rfkill state is only actionable if it
// belongs to the selected radio's sysfs PHY.
func radioUnderPHY(phy, rfkill string) bool {
	return strings.HasPrefix(filepath.Clean(rfkill), filepath.Clean(phy)+string(os.PathSeparator))
}

func linuxRadioCheck(iface string) LinkCheck {
	source := "sysfs rfkill (selected Wi-Fi PHY)"
	phy, err := filepath.EvalSymlinks(filepath.Join("/sys/class/net", iface, "phy80211"))
	if err != nil {
		return LinkCheck{"radio_block", Unknown, "unknown", source,
			"Cannot associate a radio block with the selected adapter; other blocked radios are ignored."}
	}
	dirs, err := os.ReadDir("/sys/class/rfkill")
	if err != nil {
		return LinkCheck{"radio_block", Unknown, "unknown", source, "Radio block state is not exposed."}
	}
	for _, entry := range dirs {
		path := filepath.Join("/sys/class/rfkill", entry.Name())
		real, err := filepath.EvalSymlinks(path)
		if err != nil || !radioUnderPHY(phy, real) {
			continue
		}
		typ, err := os.ReadFile(filepath.Join(path, "type"))
		if err != nil || strings.TrimSpace(string(typ)) != "wlan" {
			continue
		}
		hard, he := readLinuxLinkCounter(path, "hard")
		soft, se := readLinuxLinkCounter(path, "soft")
		if he != nil || se != nil {
			return LinkCheck{"radio_block", Unknown, "unknown", source, "Selected radio block counters not exposed."}
		}
		if hard != 0 || soft != 0 {
			return LinkCheck{"radio_block", Fail, fmt.Sprintf("hardware=%d software=%d", hard, soft),
				source, "Unblock the Wi-Fi hardware or software radio."}
		}
		return LinkCheck{"radio_block", OK, "unblocked", source, ""}
	}
	return LinkCheck{"radio_block", Unknown, "unknown", source,
		"Selected PHY has no matching rfkill entry; cannot infer radio block state."}
}
