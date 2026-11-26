//go:build windows

package diag

import (
	"net"
)

func windowsL2Evidence(o Options, gateway string, neighbors []winNeighbor, data map[string]any) []LinkCheck {
	var mac,state string
	for _,entry:=range neighbors {
		if net.ParseIP(entry.IP)!=nil && net.ParseIP(gateway)!=nil &&
			net.ParseIP(entry.IP).Equal(net.ParseIP(gateway)) {
			mac,state=entry.MAC,entry.State
			break
		}
	}
	checks:=[]LinkCheck{gatewayCacheStatus(gateway,mac,state,"Windows IPv4 GetIpNetTable (passive ARP cache)")}
	if mac!="" {data["gateway_mac"]=mac}
	data["gateway_cache_state"]=state
	checks=append(checks,LinkCheck{"gateway_ipv6_ndp",Unknown,"unknown","Windows native GetIpNetTable",
		"Windows IPv6 NDP is not implemented; this IPv4 ARP table does not describe IPv6 gateway neighbors."})
	if o.GatewayProbe {
		checks=append(checks,windowsGatewayEcho(o,gateway))
	} else {
		checks=append(checks,gatewayProbeUnknown())
	}
	if o.LLDP {
		checks=append(checks,LinkCheck{"lldp_neighbor",Unknown,"unknown","Windows network adapter",
			"No supported native read-only LLDP neighbor source implemented; switch and port are unavailable."})
	} else {
		checks=append(checks,lldpUnknown())
	}
	return checks
}

func windowsGatewayEcho(o Options, gateway string) LinkCheck {
	if net.ParseIP(gateway)==nil || net.ParseIP(gateway).To4()==nil {
		return LinkCheck{"gateway_icmp_rtt",Unknown,"unknown","native IPv4 ICMP (OSI L3)",
			"No IPv4 default next-hop to probe on this interface."}
	}
	probe:=o
	probe.Count=1
	probe.Target=gateway
	probe.Family="4"
	stats,err:=windowsPingStats(probe)
	if err!=nil {
		return LinkCheck{"gateway_icmp_rtt",Unknown,"unknown","opt-in Windows IPv4 ICMP",
			"ICMP probe unavailable: "+err.Error()}
	}
	if stats.Received==0 {
		return LinkCheck{"gateway_icmp_rtt",Warn,"no echo reply","opt-in Windows IPv4 ICMP",
			"Gateway may filter ICMP; inspect ARP cache, VLANs and switch before concluding link failure."}
	}
	return LinkCheck{"gateway_icmp_rtt",OK,stats.AvgMS,"opt-in Windows IPv4 ICMP RTT (milliseconds)",""}
}
