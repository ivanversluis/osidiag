//go:build linux

package diag

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func linuxL2Evidence(o Options, iface string, entries []NeighborEntry, data map[string]any) []LinkCheck {
	checks:=[]LinkCheck{}
	gateways:=[]linuxGateway{}
	if raw,err:=os.ReadFile("/proc/net/route");err==nil {
		if g:=defaultRouteIPv4(raw,iface);g!="" && g!="on-link" {
			gateways=append(gateways,linuxGateway{"ipv4",g})
			data["default_gateway"]=g
		}
	}
	if raw,err:=os.ReadFile("/proc/net/ipv6_route");err==nil {
		if g:=defaultRouteIPv6(raw,iface);g!="" && g!="::" {
			gateways=append(gateways,linuxGateway{"ipv6",g})
			data["ipv6_default_gateway"]=g
		}
	}
	for _,g:=range gateways {
		var mac,state string
		for _,entry:=range entries {
			if entry.Interface!=iface {continue}
			if a,b:=net.ParseIP(entry.Address),net.ParseIP(g.ip);a!=nil && b!=nil && a.Equal(b) {
				mac,state=entry.MAC,entry.State
				break
			}
		}
		c:=gatewayCacheStatus(g.ip,mac,state,"Linux RTM_GETNEIGH "+g.family)
		c.Name="gateway_neighbor_"+g.family
		checks=append(checks,c)
		if mac!="" {
			if g.family=="ipv4" {data["gateway_mac"]=mac}
			if g.family=="ipv6" {data["ipv6_gateway_mac"]=mac}
		}
		data["gateway_"+g.family+"_cache_state"]=state
	}
	if len(gateways)==0 {
		checks=append(checks,gatewayCacheStatus("","","","Linux default route"))
	}
	if o.GatewayProbe {
		checks=append(checks,linuxGatewayEcho(o,gateways))
	} else {
		checks=append(checks,gatewayProbeUnknown())
	}
	if o.LLDP {
		checks=append(checks,linuxLLDPNeighbor(iface,data))
	} else {
		checks=append(checks,lldpUnknown())
	}
	return checks
}

type linuxGateway struct{family,ip string}

func linuxGatewayEcho(o Options, gateways []linuxGateway) LinkCheck {
	if len(gateways)==0 {
		return LinkCheck{"gateway_icmp_rtt",Unknown,"unknown","optional ICMP echo (OSI L3)","No addressable default gateway on the selected interface."}
	}
	g:=gateways[0]
	if g.family=="ipv6" && net.ParseIP(g.ip).IsLinkLocalUnicast() {
		return LinkCheck{"gateway_icmp_rtt",Unknown,"unknown","optional ICMPv6 echo",
			"Link-local IPv6 next hop requires an interface-scoped probe; not yet supported."}
	}
	probe:=o
	probe.Target=g.ip
	probe.Count=1
	if g.family=="ipv6" {probe.Family="6"} else {probe.Family="4"}
	response:=PingOnly(probe)
	if response.Error!="" {
		return LinkCheck{"gateway_icmp_rtt",Unknown,"unknown","opt-in ICMP "+g.family,
			"Gateway probe unavailable: "+response.Error}
	}
	stats,ok:=response.Data["ping"].(EchoStats)
	if !ok {return LinkCheck{"gateway_icmp_rtt",Unknown,"unknown","opt-in ICMP "+g.family,"No valid ICMP probe statistics."}}
	if stats.Received==0 {
		return LinkCheck{"gateway_icmp_rtt",Warn,"no echo reply","opt-in ICMP "+g.family,
			"Gateway did not reply to ICMP. ACLs can intentionally block echo; investigate ARP/NDP and local routing."}
	}
	return LinkCheck{"gateway_icmp_rtt",OK,stats.AvgMS,"opt-in ICMP "+g.family+" echo (milliseconds)",""}
}

// LLDP is a read-only optional local-daemon query. Never start a daemon,
// enable LLDP advertisement, or send discovery frames.
func linuxLLDPNeighbor(iface string, data map[string]any) LinkCheck {
	ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
	defer cancel()
	raw,err:=exec.CommandContext(ctx,"lldpcli","-f","keyvalue","show","neighbors","ports",iface).Output()
	if err!=nil || len(raw)>64<<10 {
		return LinkCheck{"lldp_neighbor",Unknown,"unknown","optional lldpcli (read-only)",
			"LLDP daemon unavailable or output too large; switch and port are unknown."}
	}
	prefix:="lldp."+iface+"."
	sw,port:="",""
	for _,line:=range strings.Split(string(raw),"\n") {
		key,value,ok:=strings.Cut(strings.TrimSpace(line),"=")
		if !ok || !strings.HasPrefix(key,prefix) {continue}
		switch strings.TrimPrefix(key,prefix) {
		case "chassis.name":if sw=="" {sw=safeLinkText(value)}
		case "port.ifname","port.descr":if port=="" {port=safeLinkText(value)}
		}
	}
	if sw=="" && port=="" {
		return LinkCheck{"lldp_neighbor",Unknown,"unknown","optional lldpcli",
			"No switch identity or port available on the selected adapter."}
	}
	data["lldp_switch"]=sw
	data["lldp_port"]=port
	return LinkCheck{"lldp_neighbor",OK,fmt.Sprintf("%s / %s",sw,port),"local lldpcli cache",
		"LLDP reports an advertisement, not proof of switch forwarding or VLAN reachability."}
}
