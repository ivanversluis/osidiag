//go:build windows

package diag

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

func TestDefaultRoutePrefersLowestMetric(t *testing.T) {
	// 19=Hyper-V external vSwitch; 22=physical Ethernet; 3=Wi-Fi.
	buf := make([]byte, 4+3*56)
	binary.LittleEndian.PutUint32(buf[:4], 3)
	rows := []struct {
		index, metric uint32
		gateway       [4]byte
	}{
		{22, 80, [4]byte{192, 168, 1, 1}},
		{3, 40, [4]byte{192, 168, 2, 1}},
		{19, 20, [4]byte{10, 0, 0, 1}},
	}
	for j, r := range rows {
		b := buf[4+j*56 : 4+(j+1)*56]
		copy(b[12:16], r.gateway[:])
		binary.LittleEndian.PutUint32(b[16:20], r.index)
		binary.LittleEndian.PutUint32(b[36:40], r.metric)
	}
	routes, err := parseWindowsDefaultRoutes(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 || routes[0].Index != 19 || routes[0].Gateway != "10.0.0.1" {
		t.Fatalf("routes: %+v", routes)
	}
	adapters := []windowsAdapter{
		{Device: net.Interface{Index: 3, Flags: net.FlagUp}, Alias: "Wi-Fi"},
		{Device: net.Interface{Index: 19, Flags: net.FlagUp}, Alias: "vEthernet (vSwitch)"},
		{Device: net.Interface{Index: 22, Flags: net.FlagUp}, Alias: "Ethernet"},
	}
	selected, ok := selectRouteInterface(adapters, routes)
	if !ok || selected.Alias != "vEthernet (vSwitch)" || selected.Route.Gateway != "10.0.0.1" {
		t.Fatalf("wrong default-route adapter: %+v, found=%t", selected, ok)
	}
	adapters[1].Device.Flags = 0
	selected, ok = selectRouteInterface(adapters, routes)
	if !ok || selected.Alias != "Wi-Fi" {
		t.Fatalf("disconnected route not skipped: %+v, found=%t", selected, ok)
	}
}

func TestWindowsTableRejectsCorruptLength(t *testing.T) {
	buf := make([]byte, 4+56)
	binary.LittleEndian.PutUint32(buf, 100)
	if _, err := parseWindowsDefaultRoutes(buf); err == nil {
		t.Fatal("accepted corrupt route table")
	}
}

func TestWindowsNativeSocketTables(t *testing.T) {
	// Does not use PowerShell or remote network access.
	stats, err := countWindowsSockets()
	if err != nil {
		t.Fatalf("Windows IP Helper socket inspection failed: %v", err)
	}
	if stats.TCPListeners < 0 || stats.UDPSockets < 0 || stats.TCPSessions < 0 {
		t.Fatalf("invalid native stats: %+v", stats)
	}
}

func TestFriendlyAliasAndIndex(t *testing.T) {
	adapters := []windowsAdapter{{Device: net.Interface{Index: 22, Name: "{GUID-EXAMPLE}"}, Alias: "Ethernet"}}
	for _, want := range []string{"Ethernet", "ethernet", "22", "{GUID-EXAMPLE}"} {
		got, ok := matchWindowsAdapter(want, adapters)
		if !ok || got.Alias != "Ethernet" {
			t.Errorf("could not select %q", want)
		}
	}
}

func TestWindowsAliasNativeIndexRoundTrip(t *testing.T) {
    interfaces,err:=net.Interfaces()
    if err!=nil {t.Fatal(err)}
    found:=0
    for _,iface:=range interfaces {
        alias:=interfaceAlias(uint32(iface.Index))
        if alias=="" {continue}
        index,err:=windowsAliasIndex(alias)
        if err!=nil {t.Fatalf("round trip %q: %v",alias,err)}
        if index!=uint32(iface.Index) {t.Fatalf("%s: index %d, expected %d",alias,index,iface.Index)}
        found++
    }
    if found==0 {t.Skip("no Windows adapter aliases exposed in CI")}
}

func TestWindowsAdministrativeState(t *testing.T) {
	for _, tc := range []struct { admin uint32; want bool }{
		{1, true}, {2, false}, {3, false},
	} {
		if got := windowsAdminEnabled(tc.admin); got != tc.want {
			t.Errorf("admin status %d -> %t, want %t", tc.admin, got, tc.want)
		}
	}
}

func TestWindowsNativeICMPErrorClassification(t *testing.T) {
	for _, tc := range []struct { code syscall.Errno; timeout bool }{
		{11010, true}, {1460, true}, {258, true},
		{50, false}, {87, false}, {11001, false}, {0, false},
	} {
		if got := windowsICMPIsTimeout(tc.code); got != tc.timeout {
			t.Errorf("ICMP error code %d -> timeout=%t, want %t", tc.code, got, tc.timeout)
		}
	}
}
