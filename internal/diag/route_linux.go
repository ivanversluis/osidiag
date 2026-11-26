//go:build linux

package diag

import (
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"strings"
)

// defaultRouteIPv4 parses the kernel's /proc/net/route. Gateways are encoded
// as little-endian IPv4 integers, and the lowest-metric UP route is selected.
func defaultRouteIPv4(table []byte, name string) string {
	bestMetric := int(^uint(0) >> 1)
	best := ""
	for row, line := range strings.Split(string(table), "\n") {
		if row == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] != name || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&1 == 0 {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil || metric >= bestMetric {
			continue
		}
		n, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(n))
		gateway := net.IP(buf).String()
		if n == 0 {
			gateway = "on-link"
		}
		best, bestMetric = gateway, metric
	}
	return best
}

func defaultRouteIPv6(table []byte, name string) string {
	bestMetric := uint64(^uint(0) >> 1)
	best := ""
	for _, line := range strings.Split(string(table), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[9] != name || fields[0] != strings.Repeat("0", 32) || fields[1] != "00" {
			continue
		}
		metric, err := strconv.ParseUint(fields[5], 16, 32)
		if err != nil || metric >= bestMetric {
			continue
		}
		gateway := fields[4]
		if len(gateway) != 32 {
			continue
		}
		raw := make([]byte, 16)
		valid := true
		for i := 0; i < 16; i++ {
			b, e := strconv.ParseUint(gateway[2*i:2*i+2], 16, 8)
			if e != nil {
				valid = false
				break
			}
			raw[i] = byte(b)
		}
		if !valid {
			continue
		}
		best, bestMetric = net.IP(raw).String(), metric
	}
	return best
}

// routeContext documents the selected interface's addresses and default route.
// This is kernel configuration, not proof that a particular destination uses
// that interface. Route-to-target validation needs an explicit route lookup.
func routeContext(o Options, ipv6 bool) map[string]any {
	data := map[string]any{"default_gateway": "unavailable"}
	iface, err := interfaceFor(o.Interface)
	if err != nil {
		data["route_note"] = err.Error()
		return data
	}
	data["interface"] = iface.Name
	data["local_mac"] = iface.HardwareAddr.String()
	addrs, err := iface.Addrs()
	if err == nil {
		cidrs := make([]string, 0, len(addrs))
		preferred := ""
		for _, a := range addrs {
			cidrs = append(cidrs, a.String())
			ip, _, parseErr := net.ParseCIDR(a.String())
			if parseErr == nil && (ip.To4() == nil) == ipv6 && preferred == "" {
				preferred = a.String()
			}
		}
		data["interface_cidrs"] = cidrs
		if preferred != "" {
			data["local_cidr"] = preferred
		}
	}
	path := "/proc/net/route"
	if ipv6 {
		path = "/proc/net/ipv6_route"
	}
	if table, err := os.ReadFile(path); err == nil {
		gateway := ""
		if ipv6 {
			gateway = defaultRouteIPv6(table, iface.Name)
		} else {
			gateway = defaultRouteIPv4(table, iface.Name)
		}
		if gateway != "" {
			data["default_gateway"] = gateway
		}
	}
	data["route_note"] = "Default route for selected interface; an on-link or policy-routed destination may use a different next hop."
	return data
}


// defaultRouteInterfaceIPv6 picks a global IPv6 ::/0 route by metric.
// IPv6-only installations must not silently select an arbitrary adapter.
func defaultRouteInterfaceIPv6(table []byte) string {
	bestMetric := uint64(^uint(0))
	best := ""
	for _, line := range strings.Split(string(table), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[0] != strings.Repeat("0",32) || f[1] != "00" {
			continue
		}
		flags, err := strconv.ParseUint(f[8],16,32)
		if err != nil || flags&1 == 0 { continue }
		metric, err := strconv.ParseUint(f[5],16,32)
		if err != nil || metric >= bestMetric { continue }
		bestMetric, best = metric, f[9]
	}
	return best
}
