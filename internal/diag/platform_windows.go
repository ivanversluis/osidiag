//go:build windows

package diag

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Windows diagnostics use IP Helper APIs rather than launching a fresh
// PowerShell process for every layer. All APIs below are available on Win 11.
var (
	iphlp                       = syscall.NewLazyDLL("iphlpapi.dll")
	getIPForwardTable           = iphlp.NewProc("GetIpForwardTable")
	getIPNetTable               = iphlp.NewProc("GetIpNetTable")
	getExtendedTCPTable         = iphlp.NewProc("GetExtendedTcpTable")
	getExtendedUDPTable         = iphlp.NewProc("GetExtendedUdpTable")
	convertInterfaceIndexToLuid = iphlp.NewProc("ConvertInterfaceIndexToLuid")
	convertInterfaceLuidToAlias = iphlp.NewProc("ConvertInterfaceLuidToAlias")
    convertInterfaceAliasToLuid = iphlp.NewProc("ConvertInterfaceAliasToLuid")
    convertInterfaceLuidToIndex = iphlp.NewProc("ConvertInterfaceLuidToIndex")
	icmpCreateFile              = iphlp.NewProc("IcmpCreateFile")
	icmpSendEcho                = iphlp.NewProc("IcmpSendEcho")
	icmpCloseHandle             = iphlp.NewProc("IcmpCloseHandle")
)

const maxWindowsTableBytes = 32 << 20

// ipHelperTable handles the two-call size negotiation for Windows' native
// routing, ARP, TCP and UDP tables. Each call's extra args follow buffer/size.
func ipHelperTable(proc *syscall.LazyProc, extra ...uintptr) ([]byte, error) {
	var size uint32
	args := append([]uintptr{0, uintptr(unsafe.Pointer(&size))}, extra...)
	code, _, _ := proc.Call(args...)
	if code != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
		if code == 0 && size == 0 {
			return []byte{0, 0, 0, 0}, nil
		}
		return nil, fmt.Errorf("%s size: Win32 error %d", proc.Name, code)
	}
	if size < 4 || size > maxWindowsTableBytes {
		return nil, fmt.Errorf("%s unexpected table size %d", proc.Name, size)
	}
	buf := make([]byte, int(size))
	args[0] = uintptr(unsafe.Pointer(&buf[0]))
	code, _, _ = proc.Call(args...)
	if code != 0 {
		return nil, fmt.Errorf("%s: Win32 error %d", proc.Name, code)
	}
	return buf, nil
}

func tableCount(buf []byte, stride int) (int, error) {
	if len(buf) < 4 || stride <= 0 {
		return 0, fmt.Errorf("invalid Windows network table")
	}
	n := uint64(binary.LittleEndian.Uint32(buf[:4]))
	if n > uint64((len(buf)-4)/stride) {
		return 0, fmt.Errorf("malformed Windows network table: %d records", n)
	}
	return int(n), nil
}

type winDefaultRoute struct {
	Index   uint32
	Gateway string
	Metric  uint32
}

// MIB_IPFORWARDROW: 14 DWORDs; dwForwardDest, dwForwardMask,
// dwForwardNextHop, dwForwardIfIndex and dwForwardMetric1 are at offsets
// 0, 4, 12, 16 and 36 respectively.
func parseWindowsDefaultRoutes(buf []byte) ([]winDefaultRoute, error) {
	const rowSize = 56
	n, err := tableCount(buf, rowSize)
	if err != nil {
		return nil, err
	}
	out := make([]winDefaultRoute, 0, n)
	for j := 0; j < n; j++ {
		row := buf[4+j*rowSize : 4+(j+1)*rowSize]
		if binary.LittleEndian.Uint32(row[:4]) != 0 || binary.LittleEndian.Uint32(row[4:8]) != 0 {
			continue // only the IPv4 0.0.0.0/0 default routes
		}
		index := binary.LittleEndian.Uint32(row[16:20])
		if index == 0 {
			continue
		}
		out = append(out, winDefaultRoute{
			Index:   index,
			Gateway: net.IP(row[12:16]).String(),
			Metric:  binary.LittleEndian.Uint32(row[36:40]),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Metric != out[j].Metric {
			return out[i].Metric < out[j].Metric
		}
		// Prefer a real next hop when the metric ties.
		if (out[i].Gateway != "0.0.0.0") != (out[j].Gateway != "0.0.0.0") {
			return out[i].Gateway != "0.0.0.0"
		}
		return out[i].Index < out[j].Index
	})
	return out, nil
}

func windowsDefaultRoutes() ([]winDefaultRoute, error) {
	buf, err := ipHelperTable(getIPForwardTable, 0)
	if err != nil {
		return nil, err
	}
	return parseWindowsDefaultRoutes(buf)
}

// Windows' net.Interface.Name may be the adapter GUID rather than the friendly
// name returned by Get-NetAdapter. The IP Helper alias API is deterministic
// and does not require PowerShell or elevation.
func interfaceAlias(index uint32) string {
	var luid uint64
	code, _, _ := convertInterfaceIndexToLuid.Call(uintptr(index), uintptr(unsafe.Pointer(&luid)))
	if code != 0 {
		return ""
	}
	var alias [257]uint16
	code, _, _ = convertInterfaceLuidToAlias.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&alias[0])), uintptr(len(alias)))
	if code != 0 {
		return ""
	}
	return syscall.UTF16ToString(alias[:])
}

// windowsAliasIndex resolves a user-visible Windows adapter alias even when a
// physical NIC has no IP bound to it (e.g. Ethernet backing Hyper-V vSwitch).
func windowsAliasIndex(alias string) (uint32,error) {
    name,err:=syscall.UTF16PtrFromString(alias)
    if err!=nil{return 0,err}
    var luid uint64
    code,_,_:=convertInterfaceAliasToLuid.Call(uintptr(unsafe.Pointer(name)),uintptr(unsafe.Pointer(&luid)))
    if code!=0{return 0,fmt.Errorf("unknown Windows interface alias %q (Win32 %d)",alias,code)}
    var index uint32
    code,_,_ = convertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)),uintptr(unsafe.Pointer(&index)))
    if code!=0{return 0,fmt.Errorf("cannot resolve Windows interface index for %q (Win32 %d)",alias,code)}
    return index,nil
}

// Some physical adapters owned by Hyper-V's external switch do not appear
// in Go's IP-address interface list. Build an L1-only adapter from the native
// MIB interface table; it intentionally has no IP/gateway of its own.
func physicalAdapterWithoutIP(alias string) (windowsAdapter,error) {
    index,err:=windowsAliasIndex(alias)
    if err!=nil{return windowsAdapter{},err}
    row:=syscall.MibIfRow{Index:index}
    if err=syscall.GetIfEntry(&row);err!=nil{return windowsAdapter{},err}
    if row.PhysAddrLen>uint32(len(row.PhysAddr)) {return windowsAdapter{},fmt.Errorf("invalid MAC length for %s",alias)}
    flags:=net.Flags(0)
    if row.AdminStatus==1 && row.OperStatus==5 {flags |= net.FlagUp}
    if row.Type==24 {flags |= net.FlagLoopback}
    device:=net.Interface{Index:int(index),Name:alias,MTU:int(row.Mtu),Flags:flags,
        HardwareAddr:append(net.HardwareAddr(nil),row.PhysAddr[:row.PhysAddrLen]...)}
    return windowsAdapter{Device:device,Alias:alias},nil
}

type windowsAdapter struct {
	Device   net.Interface
	Alias    string
	Route    winDefaultRoute
	HasRoute bool
}

func selectRouteInterface(ifaces []windowsAdapter, routes []winDefaultRoute) (windowsAdapter, bool) {
	for _, route := range routes {
		for _, a := range ifaces {
			if uint32(a.Device.Index) == route.Index && a.Device.Flags&net.FlagUp != 0 && a.Device.Flags&net.FlagLoopback == 0 {
				a.Route, a.HasRoute = route, true
				return a, true
			}
		}
	}
	return windowsAdapter{}, false
}

// Match the user-facing adapter alias (e.g. "Ethernet"), native GUID, or
// interface index, without relying on Go's Windows InterfaceByName behavior.
func matchWindowsAdapter(wanted string, adapters []windowsAdapter) (windowsAdapter, bool) {
	for _, a := range adapters {
		if strings.EqualFold(wanted, a.Alias) || strings.EqualFold(wanted, a.Device.Name) || wanted == strconv.Itoa(a.Device.Index) {
			return a, true
		}
	}
	return windowsAdapter{}, false
}

func winInterface(o Options) (windowsAdapter, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return windowsAdapter{}, err
	}
	all := make([]windowsAdapter, 0, len(ifs))
	for _, i := range ifs {
		alias := interfaceAlias(uint32(i.Index))
		if alias == "" {
			alias = i.Name
		}
		all = append(all, windowsAdapter{Device: i, Alias: alias})
	}
	routes, routeErr := windowsDefaultRoutes()
	if o.Interface != "auto" {
		a, ok := matchWindowsAdapter(o.Interface, all)
		if !ok {
            if fallback,e:=physicalAdapterWithoutIP(o.Interface);e==nil {return fallback,nil}
            return windowsAdapter{}, fmt.Errorf("network adapter %q not found (use Get-NetAdapter to list aliases)",o.Interface)
        }
		for _, route := range routes {
			if route.Index == uint32(a.Device.Index) {
				a.Route, a.HasRoute = route, true
				break
			}
		}
		return a, nil
	}
	if a, ok := selectRouteInterface(all, routes); ok {
		return a, nil
	}
	for _, a := range all {
		if a.Device.Flags&net.FlagUp != 0 && a.Device.Flags&net.FlagLoopback == 0 {
			return a, nil
		}
	}
	if routeErr != nil {
		return windowsAdapter{}, fmt.Errorf("default route unavailable: %w", routeErr)
	}
	return windowsAdapter{}, fmt.Errorf("no active network adapter or IPv4 default route; use --iface")
}

func adapterData(a windowsAdapter) map[string]any {
	addrs, _ := a.Device.Addrs()
	cidrs := make([]string, 0, len(addrs))
	var localCIDR string
	for _, addr := range addrs {
		cidrs = append(cidrs, addr.String())
		if localCIDR == "" {
			if ip, _, err := net.ParseCIDR(addr.String()); err == nil && ip.To4() != nil {
				localCIDR = addr.String()
			}
		}
	}
	data := map[string]any{
		"interface": a.Alias, "index": a.Device.Index, "mac": a.Device.HardwareAddr.String(),
		"local_mac": a.Device.HardwareAddr.String(), "addresses": cidrs,
		"interface_cidrs": cidrs, "default_gateway": "unavailable",
		"route_note": "Windows IPv4 default route selected by route metric; VPNs and destination-specific routes can differ.",
	}
	if localCIDR != "" {
		data["local_cidr"] = localCIDR
	}
	if a.HasRoute {
		data["default_gateway"] = a.Route.Gateway
		data["default_route_metric"] = a.Route.Metric
	}
	return data
}

func Physical(o Options) Result {
	a, err := winInterface(o)
	if err != nil {
		return result(1, "Physical", Fail, "interface unavailable", nil, err)
	}
	data := adapterData(a)
	data["mtu"] = a.Device.MTU
	data["admin_up"] = nil // Unknown until native administrative status is queried.
	state := "down"
	status := Fail
	if a.Device.Flags&net.FlagUp != 0 {
		state, status = "up", OK
	}
	row := syscall.MibIfRow{Index: uint32(a.Device.Index)}
	if err := syscall.GetIfEntry(&row); err == nil {
		data["admin_up"] = windowsAdminEnabled(row.AdminStatus)
		if row.OperStatus != 5 {
			state, status = "down", Fail
		}
		if row.Speed > 0 && row.Speed < ^uint32(0) {
			data["speed_mbps"] = strconv.FormatUint(uint64(row.Speed/1000000), 10)
		} else {
			data["speed_mbps"] = "unknown"
		}
		data["if_type"] = row.Type
        if row.Type == 71 {
            if wifi, err := selectedWiFi(a, o); err == nil {
                data["wifi"] = wifi
            } else {
                data["wifi_note"] = err.Error()
            }
        }
	} else {
		data["speed_mbps"] = "unknown"
		data["speed_note"] = err.Error()
	}
	data["operstate"] = state
	data["carrier"] = state
	status = mergeLinkEvidence(data, status, (windowsLinkProbe{}).Probe(o, a.Alias))

	// Weak RSSI and obsolete Wi-Fi ciphers degrade the connection but do not
	// prove the physical link failed. Preserve the ability to test L3-L7.
	if wifi, ok := data["wifi"].(map[string]any); ok {
		checks, _ := data["checks"].([]LinkCheck)
		if security, ok := wifi["security_status"].(string); ok && security == string(Warn) {
			checks = append(checks, LinkCheck{"wifi_security", Warn, wifi["security"], "Native WLAN security attributes",
				"Use WPA2-AES/CCMP or WPA3; open, WEP and TKIP offer insufficient protection."})
			if status == OK { status = Warn }
		}
		if quality, ok := wifi["signal_quality_percent"].(uint32); ok && quality < 40 {
			checks = append(checks, LinkCheck{"wifi_signal", Warn, quality, "WLAN signal quality percentage",
				"Weak signal; check AP placement, interference and roaming."})
			if status == OK { status = Warn }
		}
		if radio, ok := wifi["radio_state"].(string); ok && radio == "off" {
			checks = append(checks, LinkCheck{"wifi_radio", Fail, radio, "WLAN hardware/software radio state",
				"Enable the wireless radio to restore connectivity."})
			status = Fail
		}
		if office, ok := wifi["wifi_office_checks"].([]LinkCheck); ok {
			for _, c := range office {
				if c.Status == Fail && c.Name == "wifi_rssi" { c.Status = Warn }
				checks = append(checks, c)
				if c.Status == Warn && status == OK { status = Warn }
			}
		}
		data["checks"] = checks
	}
	if nativeState, ok := data["operstate"].(string); ok { state = nativeState }
	return result(1, "Physical", status, a.Alias+" "+state, data, nil)
}

func ipString(ip syscall.IpAddressString) string {
	n := 0
	for n < len(ip.String) && ip.String[n] != 0 {
		n++
	}
	return string(ip.String[:n])
}
func adapterIP(ip syscall.IpAddrString) string {
	s := ipString(ip.IpAddress)
	if net.ParseIP(s) == nil {
		return ""
	}
	return s
}

func windowsIPv4Adapters() ([]syscall.IpAdapterInfo, error) {
	size := uint32(16384)
	for tries := 0; tries < 5; tries++ {
		buf := make([]byte, int(size))
		code := syscall.GetAdaptersInfo((*syscall.IpAdapterInfo)(unsafe.Pointer(&buf[0])), &size)
		if code == nil {
			out := []syscall.IpAdapterInfo{}
			for p := (*syscall.IpAdapterInfo)(unsafe.Pointer(&buf[0])); p != nil; p = p.Next {
				out = append(out, *p)
			}
			return out, nil
		}
		if code != syscall.ERROR_BUFFER_OVERFLOW || size > maxWindowsTableBytes {
			return nil, code
		}
	}
	return nil, fmt.Errorf("Windows adapter list exceeded buffer limit")
}

type winNeighbor struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	State     string `json:"state"`
}

func windowsARP(index uint32) ([]winNeighbor, error) {
	buf, err := ipHelperTable(getIPNetTable, 0)
	if err != nil {
		return nil, err
	}
	n, err := tableCount(buf, 24)
	if err != nil {
		return nil, err
	}
	neighbors := []winNeighbor{}
	for j := 0; j < n; j++ {
		row := buf[4+j*24 : 4+(j+1)*24]
		if binary.LittleEndian.Uint32(row[0:4]) != index {
			continue
		}
		ip := net.IP(row[16:20])
		if ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		length := int(binary.LittleEndian.Uint32(row[4:8]))
		if length == 0 || length > 8 {
			continue
		}
		kind := binary.LittleEndian.Uint32(row[20:24])
		state := "other"
		switch kind {
		case 2:
			state = "invalid"
		case 3:
			state = "dynamic"
		case 4:
			state = "static"
		}
		neighbors = append(neighbors, winNeighbor{
			IP: ip.String(), MAC: net.HardwareAddr(row[8 : 8+length]).String(), State: state,
		})
	}
	sort.Slice(neighbors, func(i, j int) bool { return neighbors[i].IP < neighbors[j].IP })
	return neighbors, nil
}

func Neighbors(o Options) Result {
	a, err := winInterface(o)
	if err != nil {
		return result(2, "DataLink", Fail, "adapter unavailable", nil, err)
	}
	data := adapterData(a)
	data["arp"] = []winNeighbor{}
	data["neighbors"] = []winNeighbor{}
	data["total"] = 0
	data["dhcp_note"] = "Read-only DHCP lease metadata; no DHCPDISCOVER or renew was sent."
	if all, err := windowsIPv4Adapters(); err == nil {
		for _, info := range all {
			if info.Index != uint32(a.Device.Index) {
				continue
			}
			lease := map[string]any{"enabled": info.DhcpEnabled != 0}
			if info.DhcpEnabled != 0 {
				if server := adapterIP(info.DhcpServer); server != "" {
					lease["server"] = server
				}
				if info.LeaseObtained > 0 {
					lease["obtained"] = time.Unix(info.LeaseObtained, 0).Local().Format(time.RFC3339)
				}
				if info.LeaseExpires > 0 {
					lease["expires"] = time.Unix(info.LeaseExpires, 0).Local().Format(time.RFC3339)
				}
			}
			data["dhcp"] = lease
			break
		}
	} else {
		data["dhcp_lookup_note"] = err.Error()
	}
	neighbors, err := windowsARP(uint32(a.Device.Index))
	if err != nil {
		return result(2, "DataLink", Warn, "ARP cache unavailable", data, err)
	}
	data["total"] = len(neighbors)
	gw, _ := data["default_gateway"].(string)
	for _, entry := range neighbors {
		if entry.IP == gw && entry.State != "invalid" {
			data["gateway_mac"] = entry.MAC
			break
		}
	}
	checks:=windowsL2Evidence(o,gw,neighbors,data)
	data["checks"]=checks
	if len(neighbors) > o.Limit {
		neighbors = neighbors[:o.Limit]
	}
	data["shown"] = len(neighbors)
	data["arp"] = neighbors
	data["neighbors"] = neighbors
	data["note"] = "IPv4 ARP cache excludes multicast; missing cached gateway MAC is not proof of failure. IPv6 NDP is not included."
	status := OK
	if data["total"] == 0 {
		status = Warn
	}
	for _,check:=range checks {
		if check.Status==Warn && status==OK {status=Warn}
	}
	return result(2, "DataLink", status, fmt.Sprintf("%d IPv4 ARP entries on %s", data["total"], a.Alias), data, nil)
}

// The IPv4 TCP table contains the same state records used by Get-NetTCPConnection.
// Both IPv4 and IPv6 tables are counted, without exposing endpoint addresses.
type windowsSockets struct {
	TCPListeners int
	TCPSessions  int
	UDPSockets   int
	States       map[string]int
}

var socketCache struct {
	sync.Mutex
	At    time.Time
	Value windowsSockets
	Err   error
}

func countWindowsSockets() (windowsSockets, error) {
	var out windowsSockets
	out.States = make(map[string]int)
	families := []struct {
		family         uint32
		tcpRow         int
		tcpStateOffset int
		udpRow         int
	}{
		{uint32(syscall.AF_INET), 24, 0, 12},
		{uint32(syscall.AF_INET6), 56, 48, 28},
	}
	for _, family := range families {
		tcpBuf, err := ipHelperTable(getExtendedTCPTable, 1, uintptr(family.family), 5, 0)
		if err != nil {
			return out, err
		}
		n, err := tableCount(tcpBuf, family.tcpRow)
		if err != nil {
			return out, err
		}
		for j := 0; j < n; j++ {
			row := tcpBuf[4+j*family.tcpRow : 4+(j+1)*family.tcpRow]
			state := binary.LittleEndian.Uint32(row[family.tcpStateOffset : family.tcpStateOffset+4])
			if state == 2 {
				out.TCPListeners++
			} else {
				out.TCPSessions++
				out.States[windowsTCPState(state)]++
			}
		}
		udpBuf, err := ipHelperTable(getExtendedUDPTable, 1, uintptr(family.family), 1, 0)
		if err != nil {
			return out, err
		}
		n, err = tableCount(udpBuf, family.udpRow)
		if err != nil {
			return out, err
		}
		out.UDPSockets += n
	}
	return out, nil
}

func windowsTCPState(state uint32) string {
	switch state {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RECV"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT1"
	case 7:
		return "FIN_WAIT2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	default:
		return fmt.Sprintf("STATE_%d", state)
	}
}

func cachedWindowsSockets() (windowsSockets, error) {
	socketCache.Lock()
	defer socketCache.Unlock()
	if !socketCache.At.IsZero() && time.Since(socketCache.At) < 300*time.Millisecond {
		return socketCache.Value, socketCache.Err
	}
	value, err := countWindowsSockets()
	socketCache.Value, socketCache.Err, socketCache.At = value, err, time.Now()
	return value, err
}

func localTransport(Options) Result {
	s, err := cachedWindowsSockets()
	data := map[string]any{"tcp_listeners": s.TCPListeners, "udp_sockets": s.UDPSockets}
	if err != nil {
		return result(4, "Transport", Warn, "Windows TCP/UDP table unavailable", data, err)
	}
	return result(4, "Transport", OK, fmt.Sprintf("%d TCP listeners; %d UDP sockets", s.TCPListeners, s.UDPSockets), data, nil)
}

func Sessions(Options) Result {
	s, err := cachedWindowsSockets()
	data := map[string]any{"tcp_sessions": s.TCPSessions, "states": s.States, "note": "TCP states approximate OSI layer 5."}
	if err != nil {
		return result(5, "Session", Warn, "Windows TCP session table unavailable", data, err)
	}
	data["established"] = s.States["ESTABLISHED"]
    data["time_wait"] = s.States["TIME_WAIT"]
    data["close_wait"] = s.States["CLOSE_WAIT"]
    data["note"] = "TCP connection states are a local OS snapshot, not an OSI layer-5 session test; a high sustained CLOSE_WAIT count may indicate an application failing to close sockets."
    return result(5, "Session", OK, fmt.Sprintf("%d TCP connections (%d established, %d TIME_WAIT, %d CLOSE_WAIT)",s.TCPSessions,s.States["ESTABLISHED"],s.States["TIME_WAIT"],s.States["CLOSE_WAIT"]),data,nil)
}

// The administrative flag is independent of Windows link/carrier state.
func windowsAdminEnabled(status uint32) bool { return status == 1 }

// Native ICMP errors are not all probe timeouts (IP_REQ_TIMED_OUT is 11010).
func windowsICMPIsTimeout(err error) bool {
	code, ok := err.(syscall.Errno)
	return ok && (code == 11010 || code == 1460 || code == 258)
}

func windowsPingStats(o Options) (EchoStats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*o.Timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, o.Target)
	if err != nil {
		return EchoStats{}, err
	}
	var ip net.IP
	for _, addr := range ips {
		if addr.IP.To4() != nil && o.Family != "6" {
			ip = addr.IP.To4()
			break
		}
	}
	if ip == nil {
		return EchoStats{}, fmt.Errorf("no IPv4 address available for %q (native Windows ICMP supports IPv4)", o.Target)
	}
	handle, _, winErr := icmpCreateFile.Call()
	if handle == 0 || handle == ^uintptr(0) {
		return EchoStats{}, fmt.Errorf("IcmpCreateFile: %v", winErr)
	}
	defer icmpCloseHandle.Call(handle)
	stats := EchoStats{Address: ip.String(), Sent: o.Count, Responses: []Probe{}}
	payload := []byte("osidiag")
	for j := 0; j < o.Count; j++ {
		reply := make([]byte, 256)
		start := time.Now()
		count, _, sendErr := icmpSendEcho.Call(
			handle, uintptr(binary.LittleEndian.Uint32(ip)), uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(o.Timeout.Milliseconds()),
		)
		probe := Probe{Reply: "timeout", Timeout: true}
		if count == 0 && !windowsICMPIsTimeout(sendErr) {
			if sendErr == nil || sendErr == syscall.Errno(0) {
				return stats, fmt.Errorf("IcmpSendEcho returned zero replies without a timeout status")
			}
			return stats, fmt.Errorf("IcmpSendEcho failed: %w", sendErr)
		}
		if count > 0 {
			status := binary.LittleEndian.Uint32(reply[4:8])
			probe.Timeout = false
			if status == 0 {
				probe.Reply, probe.Reached, probe.Responder = "echo-reply", true, ip.String()
				probe.RTTMS = float64(time.Since(start).Microseconds()) / 1000
				stats.Received++
				if stats.Received == 1 || probe.RTTMS < stats.MinMS {
					stats.MinMS = probe.RTTMS
				}
				if probe.RTTMS > stats.MaxMS {
					stats.MaxMS = probe.RTTMS
				}
				stats.AvgMS += probe.RTTMS
			} else if status == 11010 {
				probe.Reply, probe.Timeout = "timeout", true
			} else {
				probe.Reply = fmt.Sprintf("ICMP status %d", status)
			}
		}
		stats.Responses = append(stats.Responses, probe)
	}
	stats.LossPercent = 100 * float64(stats.Sent-stats.Received) / float64(stats.Sent)
	if stats.Received > 0 {
		stats.AvgMS /= float64(stats.Received)
	}
	return stats, nil
}

// IPv6 is an explicit compatibility fallback until native Icmp6SendEcho2 is
// implemented. It does not affect the usual IPv4 default-route fast path.
func windowsIPv6Ping(o Options) Result {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(o.Count+1)*o.Timeout+time.Duration(o.Count)*time.Second)
	defer cancel()
	args := []string{"-6", "-n", strconv.Itoa(o.Count), "-w", strconv.Itoa(int(o.Timeout.Milliseconds())), o.Target}
	out, err := exec.CommandContext(ctx, "ping.exe", args...).CombinedOutput()
	status := OK
	if err != nil {
		status = Warn
	}
	return result(3, "Network", status, "Windows IPv6 ping", map[string]any{
		"output": string(out), "note": "IPv6 uses Windows ping.exe; native IP Helper ping is IPv4-only."}, err)
}

func PingOnly(o Options) Result {
	if o.Family == "6" {
		return windowsIPv6Ping(o)
	}
	stats, err := windowsPingStats(o)
	if err != nil {
		if strings.Contains(err.Error(), "no IPv4 address") && o.Family == "auto" {
			return windowsIPv6Ping(o)
		}
		return result(3, "Network", Warn, "native IPv4 ping unavailable", nil, err)
	}
	status := OK
	if stats.Received != stats.Sent {
		status = Warn
	}
	return result(3, "Network", status,
		fmt.Sprintf("ICMP %d/%d replies, %.1f ms avg", stats.Received, stats.Sent, stats.AvgMS),
		map[string]any{"ping": stats}, nil)
}

func Network(o Options) Result {
	r := PingOnly(o)
	if a, err := winInterface(o); err == nil {
		data := adapterData(a)
		for k, v := range r.Data {
			data[k] = v
		}
		r.Data = data
	}
	return r
}

func TraceOnly(o Options) Result {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(o.Hops*3)*o.Timeout+5*time.Second)
	defer cancel()
	args := []string{"-d", "-h", strconv.Itoa(o.Hops), "-w", strconv.Itoa(int(o.Timeout.Milliseconds())), o.Target}
	output, err := exec.CommandContext(ctx, "tracert.exe", args...).CombinedOutput()
	status := OK
	if err != nil {
		status = Warn
	}
	return result(3, "Network", status, "Windows traceroute", map[string]any{
		"output": string(output), "note": "Windows tracert is an explicit slow operation; not run as part of check."}, err)
}
