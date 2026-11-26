//go:build linux

package diag

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

func interfaceFor(name string) (*net.Interface, error) {
	if name != "auto" {
		return net.InterfaceByName(name)
	}
	f, err := os.Open("/proc/net/route")
	if err == nil {
		defer f.Close()
		scan := bufio.NewScanner(f)
		selected := ""
		metricBest := int(^uint(0) >> 1)
		for scan.Scan() {
			fields := strings.Fields(scan.Text())
			if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
				continue
			}
			metric, e := strconv.Atoi(fields[6])
			if e == nil && metric < metricBest {
				selected = fields[0]
				metricBest = metric
			}
		}
		if selected != "" {
			return net.InterfaceByName(selected)
		}
	}
	// IPv6-only hosts have no 0.0.0.0/0 route. Honour the lowest
	// metric IPv6 default route before falling back to any UP adapter.
	if table, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
		if selected := defaultRouteInterfaceIPv6(table); selected != "" {
			if iface, err := net.InterfaceByName(selected); err == nil {
				return iface, nil
			}
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("no active interface; use --iface")
}
func sysString(iface, entry string) string {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", iface, entry))
	if err != nil {
		return "unavailable"
	}
	value := strings.TrimSpace(string(b))
	if value == "" || value == "-1" {
		return "unknown"
	}
	return value
}
func Physical(o Options) Result {
	iface, err := interfaceFor(o.Interface)
	if err != nil {
		return result(1, "Physical", Fail, "interface unavailable", nil, err)
	}
	state, carrier := sysString(iface.Name, "operstate"), sysString(iface.Name, "carrier")
	addrs, _ := iface.Addrs()
	addresses := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addresses = append(addresses, addr.String())
	}
	data := map[string]any{"interface": iface.Name, "index": iface.Index, "admin_up": iface.Flags&net.FlagUp != 0,
		"operstate": state, "carrier": carrier, "speed_mbps": sysString(iface.Name, "speed"),
		"duplex": sysString(iface.Name, "duplex"), "mac": iface.HardwareAddr.String(), "mtu": iface.MTU,
		"addresses": addresses, "note": "Virtual NICs, including WSL2, may not expose physical carrier, speed or duplex."}
	status := OK
	if iface.Flags&net.FlagUp == 0 || state == "down" || carrier == "0" {
		status = Fail
	} else if state == "unknown" || state == "unavailable" || carrier == "unknown" || carrier == "unavailable" {
		status = Warn
	}
	// Wi-Fi RF quality is advisory in an end-to-end "check": a weak
	// associated RSSI does not establish carrier failure.
	var officeChecks []LinkCheck
	if wifi, wifiStatus, found := wifiDetails(iface.Name); found {
		survey, checks := wifiOfficeLinux(iface.Name, wifi, o)
		for k,v := range survey { wifi[k] = v }
		officeChecks = checks
		data["wifi"] = wifi
		if wifiStatus == Warn && status == OK { status = Warn }
	}
	status = mergeLinkEvidence(data, status, (linuxLinkProbe{}).Probe(o, iface.Name))
	if len(officeChecks)>0 {
		all,_ := data["checks"].([]LinkCheck)
		for _, c := range officeChecks {
			if c.Name == "wifi_rssi" && c.Status == Fail { c.Status = Warn }
			all = append(all,c)
			if c.Status == Warn && status == OK { status = Warn }
		}
		data["checks"] = all
	}
	return result(1, "Physical", status, fmt.Sprintf("%s state=%s carrier=%s", iface.Name, state, carrier), data, nil)
}

type NeighborEntry struct {
	Interface string `json:"interface"`
	Address   string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	State     string `json:"state"`
}

func neighborState(v uint16) string {
	names := []struct {
		flag  uint16
		label string
	}{{1, "INCOMPLETE"}, {2, "REACHABLE"}, {4, "STALE"}, {8, "DELAY"}, {16, "PROBE"}, {32, "FAILED"}, {64, "NOARP"}, {128, "PERMANENT"}}
	out := []string{}
	for _, n := range names {
		if v&n.flag != 0 {
			out = append(out, n.label)
		}
	}
	if len(out) == 0 {
		return "NONE"
	}
	return strings.Join(out, "|")
}
func readNeighbors() ([]NeighborEntry, error) {
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil, err
	}
	out := []NeighborEntry{}
	for _, msg := range msgs {
		if msg.Header.Type != syscall.RTM_NEWNEIGH || len(msg.Data) < 12 {
			continue
		}
		family := int(msg.Data[0])
		if family != syscall.AF_INET && family != syscall.AF_INET6 {
			continue
		}
		index := int(int32(binary.NativeEndian.Uint32(msg.Data[4:8])))
		state := binary.NativeEndian.Uint16(msg.Data[8:10])
		iface, err := net.InterfaceByIndex(index)
		if err != nil {
			continue
		}
		item := NeighborEntry{Interface: iface.Name, State: neighborState(state)}
		for attrs := msg.Data[12:]; len(attrs) >= 4; {
			n := int(binary.NativeEndian.Uint16(attrs[:2]))
			kind := binary.NativeEndian.Uint16(attrs[2:4])
			if n < 4 || n > len(attrs) {
				break
			}
			value := attrs[4:n]
			switch kind {
			case 1:
				if (family == syscall.AF_INET && len(value) == 4) || (family == syscall.AF_INET6 && len(value) == 16) {
					item.Address = net.IP(value).String()
				}
			case 2:
				item.MAC = net.HardwareAddr(value).String()
			}
			aligned := (n + 3) &^ 3
			if aligned > len(attrs) {
				break
			}
			attrs = attrs[aligned:]
		}
		if item.Address != "" && state&64 == 0 {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface == out[j].Interface {
			return out[i].Address < out[j].Address
		}
		return out[i].Interface < out[j].Interface
	})
	return out, nil
}
func Neighbors(o Options) Result {
	iface, err := interfaceFor(o.Interface)
	if err != nil {
		return result(2, "DataLink", Fail, "interface unavailable", nil, err)
	}
	entries, err := readNeighbors()
	if err != nil {
		return result(2, "DataLink", Fail, "neighbor lookup failed", nil, err)
	}
	filtered := []NeighborEntry{}
	for _, item := range entries {
		if item.Interface == iface.Name {
			filtered = append(filtered, item)
		}
	}
	count := len(filtered)
	if count > o.Limit {
		filtered = filtered[:o.Limit]
	}
	status := OK
	if count == 0 {
		status = Warn
	}
	data := map[string]any{"interface": iface.Name, "local_mac": iface.HardwareAddr.String(), "total": count, "shown": len(filtered), "neighbors": filtered,
		"note": "Neighbor cache is observed state. STALE does not indicate failure."}
	if table, err := os.ReadFile("/proc/net/route"); err == nil {
		if gateway := defaultRouteIPv4(table, iface.Name); gateway != "" {
			data["default_gateway"] = gateway
			// Look up the gateway's MAC in the full cache, even if displayed entries are limited.
			for _, neighbor := range entries {
				if neighbor.Interface == iface.Name && neighbor.Address == gateway && neighbor.MAC != "" {
					data["gateway_mac"] = neighbor.MAC
					break
				}
			}
		}
	}
	checks:=linuxL2Evidence(o,iface.Name,entries,data)
	data["checks"]=checks
	for _,check:=range checks {
		if check.Status==Warn && status==OK { status=Warn }
	}
	return result(2, "DataLink", status, fmt.Sprintf("%d cached neighbors on %s", count, iface.Name), data, nil)
}

type SocketEntry struct {
	Protocol string `json:"protocol"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	State    string `json:"state"`
	UID      uint64 `json:"uid"`
	Inode    string `json:"inode"`
}

var tcpStates = map[uint64]string{1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV"}

func parseProcEndpoint(s string, ipv6 bool) (string, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("malformed endpoint %q", s)
	}
	bytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	length := 4
	if ipv6 {
		length = 16
	}
	if len(bytes) != length {
		return "", fmt.Errorf("bad IP address %q", s)
	}
	for i := 0; i < len(bytes); i += 4 {
		bytes[i], bytes[i+3] = bytes[i+3], bytes[i]
		bytes[i+1], bytes[i+2] = bytes[i+2], bytes[i+1]
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(net.IP(bytes).String(), strconv.Itoa(int(port))), nil
}
func parseProcSockets(content []byte, proto string, ipv6 bool) ([]SocketEntry, error) {
	out := []SocketEntry{}
	for i, line := range strings.Split(string(content), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return nil, fmt.Errorf("malformed /proc/net line %d", i+1)
		}
		local, err := parseProcEndpoint(fields[1], ipv6)
		if err != nil {
			return nil, err
		}
		remote, err := parseProcEndpoint(fields[2], ipv6)
		if err != nil {
			return nil, err
		}
		code, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			return nil, err
		}
		uid, _ := strconv.ParseUint(fields[7], 10, 64)
		state := tcpStates[code]
		if proto == "udp" {
			state = "UNCONN"
			if code == 1 {
				state = "ESTABLISHED"
			}
		}
		if state == "" {
			state = fmt.Sprintf("0x%02X", code)
		}
		suffix := "4"
		if ipv6 {
			suffix = "6"
		}
		out = append(out, SocketEntry{Protocol: proto + suffix, Local: local, Remote: remote, State: state, UID: uid, Inode: fields[9]})
	}
	return out, nil
}
func readSockets() ([]SocketEntry, error) {
	sources := []struct {
		path, proto string
		ipv6        bool
	}{
		{"/proc/net/tcp", "tcp", false}, {"/proc/net/tcp6", "tcp", true},
		{"/proc/net/udp", "udp", false}, {"/proc/net/udp6", "udp", true},
	}
	out := []SocketEntry{}
	for _, s := range sources {
		b, err := os.ReadFile(s.path)
		if os.IsNotExist(err) && s.ipv6 {
			continue
		}
		if err != nil {
			return nil, err
		}
		entries, err := parseProcSockets(b, s.proto, s.ipv6)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol == out[j].Protocol {
			return out[i].Local < out[j].Local
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out, nil
}
func localTransport(o Options) Result {
	entries, err := readSockets()
	if err != nil {
		return result(4, "Transport", Fail, "cannot inspect sockets", nil, err)
	}
	selected := []SocketEntry{}
	tcp, udp := 0, 0
	for _, s := range entries {
		if strings.HasPrefix(s.Protocol, "tcp") && s.State == "LISTEN" {
			selected = append(selected, s)
			tcp++
		}
		if strings.HasPrefix(s.Protocol, "udp") {
			selected = append(selected, s)
			udp++
		}
	}
	count := len(selected)
	if count > o.Limit {
		selected = selected[:o.Limit]
	}
	return result(4, "Transport", OK, fmt.Sprintf("%d TCP listeners; %d UDP sockets", tcp, udp),
		map[string]any{"tcp_listeners": tcp, "udp_sockets": udp, "shown": len(selected), "sockets": selected}, nil)
}
func Sessions(o Options) Result {
	entries, err := readSockets()
	if err != nil {
		return result(5, "Session", Fail, "cannot inspect sessions", nil, err)
	}
	selected := []SocketEntry{}
	states := map[string]int{}
	for _, s := range entries {
		if !strings.HasPrefix(s.Protocol, "tcp") || s.State == "LISTEN" {
			continue
		}
		states[s.State]++
		selected = append(selected, s)
	}
	count := len(selected)
	if count > o.Limit {
		selected = selected[:o.Limit]
	}
	return result(5, "Session", OK, fmt.Sprintf("%d TCP connections (%d established, %d TIME_WAIT, %d CLOSE_WAIT)", count, states["ESTABLISHED"],states["TIME_WAIT"], states["CLOSE_WAIT"]),
		map[string]any{"states": states, "total": count, "shown": len(selected), "sockets": selected,
			"note": "TCP connection states are a local OS snapshot, not a full OSI layer-5 session test; sustained CLOSE_WAIT may indicate application cleanup problems."}, nil)
}
