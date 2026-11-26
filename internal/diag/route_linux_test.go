//go:build linux

package diag

import (
	"strings"
	"testing"
)

func TestDefaultRouteIPv4SelectsLowestMetricAndDecodesGateway(t *testing.T) {
	table := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 FE1410AC 0003 0 0 100 00000000 0 0 0\n" +
		"eth0 00000000 0100000A 0003 0 0 500 00000000 0 0 0\n" +
		"eth0 001410AC 00000000 0001 0 0 0 00FFFFFF 0 0 0\n"
	if got := defaultRouteIPv4([]byte(table), "eth0"); got != "172.16.20.254" {
		t.Fatalf("default gateway %s", got)
	}
	if got := defaultRouteIPv4([]byte(table), "wlan0"); got != "" {
		t.Fatalf("unexpected gateway: %s", got)
	}
}

func TestDefaultRouteIPv4SkipsDownEntries(t *testing.T) {
	data := "Iface Destination Gateway Flags RefCnt Use Metric Mask\n" +
		"eth0 00000000 FE1410AC 0002 0 0 0 00000000\n"
	if got := defaultRouteIPv4([]byte(data), "eth0"); got != "" {
		t.Fatalf("down route selected: %q", got)
	}
}

func TestDefaultRouteIPv6(t *testing.T) {
	route := strings.Repeat("0", 32) + " 00 " + strings.Repeat("0", 32) + " 00 " +
		"fe800000000000000000000000000001 00000001 00000000 00000000 00000003 eth0\n"
	if got := defaultRouteIPv6([]byte(route), "eth0"); got != "fe80::1" {
		t.Fatalf("v6 gateway: %s", got)
	}
	if got := defaultRouteIPv6([]byte(route), "wlan0"); got != "" {
		t.Fatalf("unexpected v6 route: %s", got)
	}
}
