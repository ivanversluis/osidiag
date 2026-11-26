package diag

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

// Transport reports both local socket context and a targeted direct TCP
// handshake. A listener count alone never establishes target reachability.
// Corporate HTTP proxies can make application traffic succeed when direct
// TCP is blocked; in that situation the direct probe is a warning, not proof
// that the remote application is down.
func Transport(o Options) Result {
	r := localTransport(o)
	if r.Data == nil {
		r.Data = map[string]any{}
	}
	destination := net.JoinHostPort(o.Target, strconv.Itoa(o.Port))
	r.Data["target_tcp_address"] = destination
	r.Data["transport_note"] = "Local TCP listener/UDP endpoint counts describe this computer, not the destination. The outbound TCP probe is direct (does not use an HTTP proxy)."
	dialer := net.Dialer{Timeout: o.Timeout}
	start := time.Now()
	conn, err := dialer.Dial("tcp", destination)
	if err != nil {
		r.Data["tcp_reachable"] = false
		r.Data["tcp_error"] = err.Error()
		if r.Status == OK {
			r.Status = Warn
		}
		r.Summary = fmt.Sprintf("direct TCP %s unavailable; %s (local)", destination, r.Summary)
		return r
	}
	_ = conn.Close()
	ms := time.Since(start).Milliseconds()
	r.Data["tcp_reachable"] = true
	r.Data["tcp_connect_ms"] = ms
	r.Summary = fmt.Sprintf("TCP %s reachable (%d ms); %s (local)", destination, ms, r.Summary)
	return r
}