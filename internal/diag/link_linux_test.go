//go:build linux

package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxLinkStatsAndMissing(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root,"statistics"),0700);err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(filepath.Join(root,"statistics","rx_errors"),[]byte("123\n"),0600);err!=nil{t.Fatal(err)}
	values,missing:=readLinuxStats(root,[]string{"rx_errors","rx_dropped"})
	if values["rx_errors"]!=123 || len(missing)!=1 || missing[0]!="rx_dropped" {
		t.Fatalf("values=%v, missing=%v",values,missing)
	}
	if got:=uniqueSorted([]string{"rx","tx","rx"});len(got)!=2 || got[0]!="rx" {
		t.Fatalf("deduplication broken: %v",got)
	}
}

func TestLinuxIPv6DefaultInterfaceSelection(t *testing.T) {
	z := strings.Repeat("0",32)
	// /proc/net/ipv6_route has destination, prefix, source, prefix,
	// gateway, metric, ref, use, flags, interface.
	table := []byte(
		z+" 00 "+z+" 00 "+z+" 00000064 00000000 00000000 00000001 eth0\n"+
		z+" 00 "+z+" 00 "+z+" 00000014 00000000 00000000 00000001 wlan0\n"+
		z+" 00 "+z+" 00 "+z+" 00000001 00000000 00000000 00000000 dummy0\n")
	if selected:=defaultRouteInterfaceIPv6(table);selected!="wlan0" {
		t.Fatalf("selected %q, want wlan0",selected)
	}
	if selected:=defaultRouteInterfaceIPv6([]byte("not a route\n")); selected!="" {
		t.Fatalf("should not invent an IPv6 route: %q",selected)
	}
}

func TestRFKillMatchesSelectedPHYOnly(t *testing.T) {
	phy := "/sys/devices/pci0000:00/ieee80211/phy0"
	for _, tc := range []struct{ radio string; want bool }{
		{phy + "/rfkill1", true},
		{phy + "/device/rfkill2", true},
		{"/sys/devices/pci0000:00/ieee80211/phy1/rfkill3", false},
		{phy + "-other/rfkill4", false},
	} {
		if got := radioUnderPHY(phy, tc.radio); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.radio, got, tc.want)
		}
	}
}
