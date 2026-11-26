package diag

import (
	"net"
	"strings"
	"unicode"
	"unicode/utf8"
)

// gatewayCacheStatus classifies only observed ARP/NDP cache state. It cannot
// infer L3 reachability: FAILED can be transient, STALE is normal, and Windows
// dynamic ARP does not expose the Linux per-neighbor reachability state.
func gatewayCacheStatus(address, mac, state, source string) LinkCheck {
	if net.ParseIP(address)==nil {
		return LinkCheck{"gateway_neighbor",Unknown,"not applicable",source,
			"No directly-addressed default next-hop on this interface."}
	}
	if strings.EqualFold(state,"FAILED") || strings.EqualFold(state,"INCOMPLETE") || strings.EqualFold(state,"INVALID") {
		return LinkCheck{"gateway_neighbor",Warn,state,source,
			"Gateway neighbor resolution failed/incomplete; examine VLAN, switch and ARP/NDP before inferring an outage."}
	}
	if mac=="" {
		return LinkCheck{"gateway_neighbor",Unknown,"not cached",source,
			"No cached gateway MAC; send ordinary traffic or opt in to --gateway-probe. Cache absence is not proof of failure."}
	}
	switch strings.ToUpper(state) {
	case "FAILED","INCOMPLETE","INVALID":
		return LinkCheck{"gateway_neighbor",Warn,state,source,
			"Gateway neighbor resolution has a non-reachable state; check VLAN, switch and ARP/NDP traffic."}
	case "REACHABLE":
		return LinkCheck{"gateway_neighbor",OK,mac+" reachable",source,""}
	case "STALE","DELAY","PROBE","PERMANENT","STATIC":
		return LinkCheck{"gateway_neighbor",OK,mac+" "+strings.ToLower(state),source,
			"Cached gateway neighbor state is not a fresh RTT or end-to-end reachability test."}
	case "DYNAMIC","OTHER":
		return LinkCheck{"gateway_neighbor",Unknown,mac+" cached",source,
			"Windows ARP cache is passive and does not prove the gateway currently responds."}
	default:
		return LinkCheck{"gateway_neighbor",Unknown,mac+" "+state,source,
			"Unknown neighbor state."}
	}
}

func gatewayProbeUnknown() LinkCheck {
	return LinkCheck{"gateway_icmp_rtt",Unknown,"not run","optional ICMP echo (OSI L3)",
		"Use --gateway-probe to test RTT to the IPv4 default gateway. ICMP policy can block replies."}
}

func lldpUnknown() LinkCheck {
	return LinkCheck{"lldp_neighbor",Unknown,"not queried","optional read-only LLDP inventory",
		"Use --lldp to read a local LLDP daemon if available. Absence of LLDP does not imply an unplugged cable."}
}


func safeLinkText(input string) string {
	input=strings.TrimSpace(input)
	if !utf8.ValidString(input) {return "unknown"}
	runes:=[]rune(input)
	if len(runes)>128 {runes=runes[:128]}
	for _,r:=range runes {
		if !unicode.IsPrint(r) {return "unknown"}
	}
	return string(runes)
}
