//go:build linux

package diag

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

type icmpRunner struct {
	conn *net.IPConn
	dst  net.IPAddr
	v6   bool
	id   uint16
	seq  uint16
}

func resolveTarget(o Options) (net.IPAddr, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.Timeout*3)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, o.Target)
	if err != nil {
		return net.IPAddr{}, false, fmt.Errorf("resolve %s: %w", o.Target, err)
	}
	for _, a := range addrs {
		if a.IP.To4() != nil && o.Family != "6" {
			return a, false, nil
		}
	}
	for _, a := range addrs {
		if a.IP.To4() == nil && o.Family != "4" {
			return a, true, nil
		}
	}
	return net.IPAddr{}, false, fmt.Errorf("no address for %s and IP family %s", o.Target, o.Family)
}
func newRunner(dst net.IPAddr, v6 bool) (*icmpRunner, error) {
	network, address := "ip4:icmp", "0.0.0.0"
	if v6 {
		network, address = "ip6:ipv6-icmp", "::"
	}
	pc, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, fmt.Errorf("raw ICMP socket (CAP_NET_RAW required): %w", err)
	}
	c, ok := pc.(*net.IPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("unexpected raw socket connection type")
	}
	var seed [2]byte
	if _, err = rand.Read(seed[:]); err != nil {
		_ = c.Close()
		return nil, err
	}
	return &icmpRunner{conn: c, dst: dst, v6: v6, id: binary.BigEndian.Uint16(seed[:])}, nil
}
func (r *icmpRunner) close() { _ = r.conn.Close() }
func (r *icmpRunner) setHopLimit(ttl int) error {
	raw, err := r.conn.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	err = raw.Control(func(fd uintptr) {
		if r.v6 {
			inner = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		} else {
			inner = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		}
	})
	if err != nil {
		return err
	}
	return inner
}
func checksum(b []byte) uint16 {
	sum := uint32(0)
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
func echoRequest(v6 bool, id, seq uint16) []byte {
	b := make([]byte, 16)
	if v6 {
		b[0] = 128
	} else {
		b[0] = 8
	}
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], []byte("osidiag!"))
	if !v6 {
		binary.BigEndian.PutUint16(b[2:4], checksum(b))
	}
	return b
}
func stripIPv4Header(packet []byte) []byte {
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		length := int(packet[0]&15) * 4
		if length >= 20 && length <= len(packet) && packet[9] == 1 {
			return packet[length:]
		}
	}
	return packet
}
func matchReply(packet []byte, v6 bool, id, seq uint16, dst net.IP) (string, bool, bool) {
	if !v6 {
		packet = stripIPv4Header(packet)
	}
	if len(packet) < 8 {
		return "", false, false
	}
	kind, code := packet[0], packet[1]
	reply, ttl, unreachable := byte(0), byte(11), byte(3)
	if v6 {
		reply, ttl, unreachable = 129, 3, 1
	}
	matches := func(p []byte) bool {
		return len(p) >= 8 && binary.BigEndian.Uint16(p[4:6]) == id && binary.BigEndian.Uint16(p[6:8]) == seq
	}
	if kind == reply && code == 0 && matches(packet) {
		return "echo-reply", true, true
	}
	if kind != ttl && kind != unreachable {
		return "", false, false
	}
	inner := packet[8:]
	if v6 {
		if len(inner) < 48 || inner[0]>>4 != 6 || inner[6] != 58 {
			return "", false, false
		}
		if !net.IP(inner[24:40]).Equal(dst) {
			return "", false, false
		}
		inner = inner[40:]
	} else {
		if len(inner) < 28 || inner[0]>>4 != 4 {
			return "", false, false
		}
		n := int(inner[0]&15) * 4
		if n < 20 || len(inner) < n+8 || inner[9] != 1 {
			return "", false, false
		}
		if !net.IP(inner[16:20]).Equal(dst) {
			return "", false, false
		}
		inner = inner[n:]
	}
	requestKind := byte(8)
	if v6 {
		requestKind = 128
	}
	if inner[0] != requestKind || !matches(inner) {
		return "", false, false
	}
	if kind == ttl {
		return "time-exceeded", false, true
	}
	return fmt.Sprintf("unreachable(code=%d)", code), false, true
}
func (r *icmpRunner) probe(ttl int, timeout time.Duration) (Probe, error) {
	r.seq++
	if err := r.setHopLimit(ttl); err != nil {
		return Probe{}, err
	}
	packet := echoRequest(r.v6, r.id, r.seq)
	start := time.Now()
	if _, err := r.conn.WriteToIP(packet, &r.dst); err != nil {
		return Probe{}, err
	}
	deadline := start.Add(timeout)
	buf := make([]byte, 4096)
	for {
		if err := r.conn.SetReadDeadline(deadline); err != nil {
			return Probe{}, err
		}
		n, src, err := r.conn.ReadFromIP(buf)
		if err != nil {
			var networkErr net.Error
			if errors.As(err, &networkErr) && networkErr.Timeout() {
				return Probe{Reply: "timeout", Timeout: true}, nil
			}
			return Probe{}, err
		}
		reply, reached, matched := matchReply(buf[:n], r.v6, r.id, r.seq, r.dst.IP)
		if !matched {
			continue
		}
		if reached && !src.IP.Equal(r.dst.IP) {
			continue
		}
		return Probe{Responder: src.IP.String(), Reply: reply, Reached: reached,
			RTTMS: float64(time.Since(start).Microseconds()) / 1000}, nil
	}
}
func ping(r *icmpRunner, count int, timeout time.Duration) (EchoStats, error) {
	stats := EchoStats{Address: r.dst.String(), Sent: count, Responses: make([]Probe, 0, count)}
	var min, max, total float64
	for i := 0; i < count; i++ {
		p, err := r.probe(64, timeout)
		if err != nil {
			return stats, err
		}
		stats.Responses = append(stats.Responses, p)
		if p.Reached {
			stats.Received++
			total += p.RTTMS
			if stats.Received == 1 || p.RTTMS < min {
				min = p.RTTMS
			}
			if p.RTTMS > max {
				max = p.RTTMS
			}
		}
	}
	stats.LossPercent = 100 * float64(stats.Sent-stats.Received) / float64(stats.Sent)
	if stats.Received > 0 {
		stats.MinMS = min
		stats.AvgMS = total / float64(stats.Received)
		stats.MaxMS = max
	}
	return stats, nil
}
func trace(r *icmpRunner, maxHops, probes int, timeout time.Duration) (TraceStats, error) {
	stats := TraceStats{Address: r.dst.String(), Hops: make([]TraceHop, 0, maxHops),
		Note: "Routers can rate-limit ICMP; hop loss is not forwarded traffic loss."}
	for ttl := 1; ttl <= maxHops; ttl++ {
		hop := TraceHop{TTL: ttl, Probes: make([]Probe, 0, probes)}
		received := 0
		terminal := false
		for i := 0; i < probes; i++ {
			p, err := r.probe(ttl, timeout)
			if err != nil {
				return stats, err
			}
			hop.Probes = append(hop.Probes, p)
			if !p.Timeout {
				received++
			}
			if p.Reached {
				stats.Reached = true
				hop.Reached = true
				terminal = true
			}
			if strings.HasPrefix(p.Reply, "unreachable") {
				terminal = true
			}
		}
		hop.LossPercent = 100 * float64(probes-received) / float64(probes)
		stats.Hops = append(stats.Hops, hop)
		if terminal {
			break
		}
	}
	return stats, nil
}
func Network(o Options) Result {
	dst, v6, err := resolveTarget(o)
	if err != nil {
		return result(3, "Network", Fail, "target resolution failed", nil, err)
	}
	family := 4
	if v6 {
		family = 6
	}
	data := routeContext(o, v6)
	data["resolved_ip"] = dst.String()
	data["ip_family"] = family
	r, err := newRunner(dst, v6)
	if err != nil {
		return result(3, "Network", Warn, "ICMP probing unavailable", data, err)
	}
	defer r.close()
	p, err := ping(r, o.Count, o.Timeout)
	if err != nil {
		return result(3, "Network", Warn, "ICMP echo failed", data, err)
	}
	data["ping"] = p
	t, err := trace(r, o.Hops, o.Probes, o.Timeout)
	if err != nil {
		return result(3, "Network", Warn, "traceroute failed", data, err)
	}
	data["trace"] = t
	status := OK
	if p.LossPercent > 0 || !t.Reached {
		status = Warn
	}
	return result(3, "Network", status, fmt.Sprintf("ICMP %d/%d; traceroute reached=%v (%d hops)",
		p.Received, p.Sent, t.Reached, len(t.Hops)), data, nil)
}
func PingOnly(o Options) Result {
	dst, v6, err := resolveTarget(o)
	if err != nil {
		return result(3, "Network", Fail, "resolution failed", nil, err)
	}
	r, err := newRunner(dst, v6)
	if err != nil {
		return result(3, "Network", Warn, "ICMP unavailable", nil, err)
	}
	defer r.close()
	p, err := ping(r, o.Count, o.Timeout)
	if err != nil {
		return result(3, "Network", Warn, "ping failed", nil, err)
	}
	status := OK
	if p.LossPercent > 0 {
		status = Warn
	}
	data := routeContext(o, v6)
	data["ping"] = p
	return result(3, "Network", status, fmt.Sprintf("ICMP %d/%d replies", p.Received, p.Sent), data, nil)
}
func TraceOnly(o Options) Result {
	dst, v6, err := resolveTarget(o)
	if err != nil {
		return result(3, "Network", Fail, "resolution failed", nil, err)
	}
	r, err := newRunner(dst, v6)
	if err != nil {
		return result(3, "Network", Warn, "ICMP unavailable", nil, err)
	}
	defer r.close()
	t, err := trace(r, o.Hops, o.Probes, o.Timeout)
	if err != nil {
		return result(3, "Network", Warn, "traceroute failed", nil, err)
	}
	status := OK
	if !t.Reached {
		status = Warn
	}
	data := routeContext(o, v6)
	data["trace"] = t
	return result(3, "Network", status, fmt.Sprintf("traceroute reached=%v (%d hops)", t.Reached, len(t.Hops)), data, nil)
}
