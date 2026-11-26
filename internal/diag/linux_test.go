//go:build linux

package diag

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestParseProcEndpoint(t *testing.T) {
	cases := []struct {
		value string
		v6    bool
		want  string
	}{
		{"0100007F:1F90", false, "127.0.0.1:8080"},
		{"00000000:0050", false, "0.0.0.0:80"},
		{"00000000000000000000000001000000:01BB", true, "[::1]:443"},
	}
	for _, tc := range cases {
		got, err := parseProcEndpoint(tc.value, tc.v6)
		if err != nil || got != tc.want {
			t.Errorf("got %q, err %v; want %q", got, err, tc.want)
		}
	}
	if _, err := parseProcEndpoint("bad", false); err == nil {
		t.Error("invalid endpoint accepted")
	}
}
func TestSocketDecode(t *testing.T) {
	sample := "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000\n"
	entries, err := parseProcSockets([]byte(sample), "tcp", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Local != "127.0.0.1:8080" || entries[0].State != "LISTEN" || entries[0].Inode != "12345" {
		t.Fatalf("socket parse: %+v", entries)
	}
}
func TestICMPChecksumAndMatch(t *testing.T) {
	const id, seq = 0x1234, 0x5678
	echo := echoRequest(false, id, seq)
	if checksum(echo) != 0 {
		t.Fatalf("checksum %x", checksum(echo))
	}
	response := append([]byte(nil), echo...)
	response[0] = 0
	binary.BigEndian.PutUint16(response[2:4], 0)
	binary.BigEndian.PutUint16(response[2:4], checksum(response))
	kind, reached, match := matchReply(response, false, id, seq, net.ParseIP("127.0.0.1"))
	if kind != "echo-reply" || !reached || !match {
		t.Fatalf("reply %s %v %v", kind, reached, match)
	}
	_, _, match = matchReply(response, false, id+1, seq, net.ParseIP("127.0.0.1"))
	if match {
		t.Fatal("accepted unrelated probe ID")
	}
}
func TestICMPTimeExceeded(t *testing.T) {
	target := net.ParseIP("198.51.100.5").To4()
	inner := make([]byte, 20)
	inner[0] = 0x45
	inner[9] = 1
	copy(inner[16:20], target)
	packet := append([]byte{11, 0, 0, 0, 0, 0, 0, 0}, append(inner, echoRequest(false, 100, 300)...)...)
	kind, reached, match := matchReply(packet, false, 100, 300, target)
	if kind != "time-exceeded" || reached || !match {
		t.Fatalf("hop %s %v %v", kind, reached, match)
	}
}
func TestICMPv6TimeExceeded(t *testing.T) {
	target := net.ParseIP("2001:db8::b")
	inner := make([]byte, 40)
	inner[0] = 0x60
	inner[6] = 58
	copy(inner[24:40], target)
	packet := append([]byte{3, 0, 0, 0, 0, 0, 0, 0}, append(inner, echoRequest(true, 34, 56)...)...)
	kind, reached, match := matchReply(packet, true, 34, 56, target)
	if kind != "time-exceeded" || reached || !match {
		t.Fatalf("v6 %s %v %v", kind, reached, match)
	}
}
func TestNeighborState(t *testing.T) {
	if neighborState(4) != "STALE" {
		t.Fatal(neighborState(4))
	}
	if s := neighborState(34); !strings.Contains(s, "REACHABLE") || !strings.Contains(s, "FAILED") {
		t.Fatal(s)
	}
}
