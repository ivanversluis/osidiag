//go:build windows

package diag

import (
	"fmt"
	"strconv"
	"time"
	"unsafe"
)

// MIB_IF_ROW2 follows the Windows SDK's IP Helper ABI. In particular,
// Alias and Description are WCHAR[257] and native counters are 64-bit.
type mibIfRow2 struct {
	Luid uint64
	Index uint32
	GUID [16]byte
	Alias [257]uint16
	Description [257]uint16
	PhysicalAddressLength uint32
	PhysicalAddress [32]byte
	PermanentPhysicalAddress [32]byte
	MTU uint32
	Type uint32
	TunnelType uint32
	MediaType uint32
	PhysicalMediumType uint32
	AccessType uint32
	DirectionType uint32
	Flags byte
	_ [3]byte
	OperStatus uint32
	AdminStatus uint32
	MediaConnectState uint32
	NetworkGUID [16]byte
	ConnectionType uint32
	_ [4]byte
	TxLinkSpeed uint64
	RxLinkSpeed uint64
	InOctets uint64
	InUcastPkts uint64
	InNUcastPkts uint64
	InDiscards uint64
	InErrors uint64
	InUnknownProtos uint64
	InUcastOctets uint64
	InMulticastOctets uint64
	InBroadcastOctets uint64
	OutOctets uint64
	OutUcastPkts uint64
	OutNUcastPkts uint64
	OutDiscards uint64
	OutErrors uint64
	OutUcastOctets uint64
	OutMulticastOctets uint64
	OutBroadcastOctets uint64
	OutQLen uint64
}

var getIfEntry2 = iphlp.NewProc("GetIfEntry2")

func windowsRow2(index uint32) (mibIfRow2, error) {
	row := mibIfRow2{Index: index}
	code, _, _ := getIfEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 {
		return row, fmt.Errorf("GetIfEntry2 interface %d: Win32 error %d", index, code)
	}
	return row, nil
}

type windowsLinkProbe struct{}

func windowsErrorCounters(row mibIfRow2) map[string]uint64 {
	return map[string]uint64{
		"rx_errors": row.InErrors,
		"tx_errors": row.OutErrors,
		"rx_dropped": row.InDiscards,
		"tx_dropped": row.OutDiscards,
	}
}

func (windowsLinkProbe) Probe(o Options, name string) LinkEvidence {
	e := LinkEvidence{Fields: map[string]any{}, Checks: []LinkCheck{}}
	add := func(c LinkCheck) {e.Checks = append(e.Checks,c)}
	a, err := winInterface(Options{Interface:name})
	if err != nil {
		add(LinkCheck{"interface", Unknown, "unknown", "IP Helper", err.Error()})
		return e
	}
	row, err := windowsRow2(uint32(a.Device.Index))
	if err != nil {
		add(LinkCheck{"native_link_state", Unknown, "unknown", "GetIfEntry2", err.Error()})
		return e
	}
	kind := "virtual"
	switch {
	case row.Type == 71:
		kind = "wifi"
	case row.Flags&1 != 0:
		kind = "ethernet"
	}
	e.Fields["link_kind"] = kind
	e.Fields["if_type"] = row.Type
	if kind == "virtual" {
		add(LinkCheck{"interface_kind", Unknown, kind, "MIB_IF_ROW2 HardwareInterface flag",
			"Default route uses a virtual adapter; inspect its physical uplink separately."})
	} else {
		add(LinkCheck{"interface_kind", OK, kind, "MIB_IF_ROW2 HardwareInterface flag", ""})
	}
	e.Fields["admin_up"] = row.AdminStatus == 1
	switch row.AdminStatus {
	case 1:
		add(LinkCheck{"administrative_state", OK, "enabled", "GetIfEntry2", ""})
	case 2:
		add(LinkCheck{"administrative_state", Fail, "disabled", "GetIfEntry2",
			"Enable the adapter in Windows network settings."})
	default:
		add(LinkCheck{"administrative_state", Unknown, "unknown", "GetIfEntry2", ""})
	}
	op := "unknown"
	switch row.OperStatus {
	case 1:
		op = "up"
	case 2, 6, 7:
		op = "down"
	case 5:
		op = "dormant"
	}
	e.Fields["operstate"] = op
	if op == "down" {
		add(LinkCheck{"operational_state", Fail, op, "GetIfEntry2",
			"Check link, adapter and upstream switch."})
	} else if op == "up" {
		add(LinkCheck{"operational_state", OK, op, "GetIfEntry2", ""})
	} else {
		add(LinkCheck{"operational_state", Unknown, op, "GetIfEntry2", ""})
	}
	media := "unknown"
	switch row.MediaConnectState {
	case 1:
		media = "connected"
	case 2:
		media = "disconnected"
	}
	e.Fields["carrier"] = media
	if media == "disconnected" {
		add(LinkCheck{"carrier", Fail, media, "GetIfEntry2", "Connect the cable or associate to a Wi-Fi AP."})
	} else if media == "connected" {
		add(LinkCheck{"carrier", OK, media, "GetIfEntry2", ""})
	} else {
		add(LinkCheck{"carrier", Unknown, media, "GetIfEntry2", ""})
	}
	speed := float64(row.TxLinkSpeed)
	if row.RxLinkSpeed < row.TxLinkSpeed || speed == 0 {
		speed = float64(row.RxLinkSpeed)
	}
	speed /= 1e6
	if speed > 0 {
		e.Fields["speed_mbps"] = strconv.FormatFloat(speed,'f',0,64)
	} else {
		e.Fields["speed_mbps"] = "unknown"
	}
	if kind == "wifi" {
		add(LinkCheck{"link_speed", Unknown, "use associated Wi-Fi PHY rate", "GetIfEntry2", ""})
	} else if kind == "virtual" {
		add(LinkCheck{"link_speed", Unknown, speed, "GetIfEntry2",
			"Virtual interface speed does not prove physical NIC speed."})
	} else {
		add(speedCheck(speed,o.MinLinkMbps,"GetIfEntry2 negotiated TX/RX link speed"))
	}
	add(LinkCheck{"duplex", Unknown, "unknown", "GetIfEntry2",
		"Windows IP Helper does not expose duplex; use adapter driver-specific CIM properties."})
	add(LinkCheck{"driver", Unknown, "unknown", "GetIfEntry2",
		"Driver name requires a separate Plug and Play query."})
	add(LinkCheck{"link_flaps", Unknown, "unknown", "GetIfEntry2",
		"Link flap count and last-change timestamp are not exposed by this API."})
	add(LinkCheck{"crc_fcs", Unknown, "unknown", "GetIfEntry2",
		"Detailed CRC/FCS and retry counters require driver-specific statistics."})
	add(LinkCheck{"cable_test", Unknown, "not run", "NIC TDR",
		"Cable TDR is disruptive and requires explicit driver support."})
	add(LinkCheck{"optical_power", Unknown, "unknown", "SFP driver diagnostics", ""})

	if o.LinkSample > 0 {
		begin := time.Now()
		time.Sleep(o.LinkSample)
		second, err := windowsRow2(uint32(a.Device.Index))
		if err != nil {
			add(LinkCheck{"link_errors", Unknown, "unknown", "GetIfEntry2", err.Error()})
		} else {
			rates, reset := counterRates(windowsErrorCounters(row), windowsErrorCounters(second), time.Since(begin))
			e.Fields["error_rates_per_sec"] = rates
			e.Fields["counter_sample_seconds"] = time.Since(begin).Seconds()
			add(counterCheck(rates,reset,"GetIfEntry2 (64-bit counters, two samples)"))
		}
	} else {
		add(LinkCheck{"link_errors", Unknown, "not sampled", "GetIfEntry2",
			"Use --link-sample 5s to capture per-second errors/drops."})
	}
	return e
}
