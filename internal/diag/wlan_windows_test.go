//go:build windows

package diag

import (
	"strings"
	"fmt"
	"net"
	"testing"
	"unsafe"
)

func TestWirelessSSIDAndInterfacePriority(t *testing.T) {
	items := []wifiConnection{
		{Alias: "Local Area Connection* 1", State: 4},
		{Alias: "Wi-Fi", State: 1, SSID: "Meraki-Guest", BSSID: "ac:de:48:00:11:22", Quality: 85},
	}
	got, ok := chooseWiFiConnection(items, "auto", 0)
	if !ok || got.Alias != "Wi-Fi" {
		t.Fatalf("auto selected %q (%v)", got.Alias, ok)
	}
	got, ok = chooseWiFiConnection(items, "Wi-Fi", 0)
	if !ok || got.BSSID != "ac:de:48:00:11:22" {
		t.Fatal("explicit interface ignored")
	}
	got, ok = chooseWiFiConnection(items, "Local Area Connection* 1", 0)
	if !ok || got.State != 4 {
		t.Fatal("explicit disconnected adapter ignored")
	}
}
func TestWLANSSIDUnicodeAndBinary(t *testing.T) {
	var s wlanSSID
	copy(s.Bytes[:], []byte("Coffee-WiFi"))
	s.Length = 11
	if got := ssidText(s); got != "Coffee-WiFi" {
		t.Fatalf("ssid %q", got)
	}
	s.Bytes[0] = 0xff
	s.Length = 1
	if got := ssidText(s); got != "hex:ff" {
		t.Fatalf("binary ssid %q", got)
	}
	s.Bytes[0] = 0x1b
    s.Length = 1
    if got:=ssidText(s);got!="hex:1b" {t.Fatalf("control character leaked: %q",got)}
    s.Length = 33
	if ssidText(s) != "" {
		t.Fatal("invalid length accepted")
	}
}
func TestWLANAttributeLayout(t *testing.T) {
	if off := unsafe.Offsetof(wlanConnection{}.Association); off != 520 {
		t.Fatalf("association offset %d", off)
	}
	if n := unsafe.Sizeof(wlanAssociation{}); n != 68 {
		t.Fatalf("WLAN association layout %d", n)
	}
	if !strings.EqualFold(guidNormalized("{ABC-def}"), "abc-def") {
		t.Fatal("GUID normalization")
	}
}
func TestWirelessResolvesExplicitInterfaceNotDefault(t *testing.T) {
	for _, wanted := range []string{"auto", "Wi-Fi", "18", "Ethernet", "missing"} {
		seen := ""
		index := selectedWiFiInterfaceIndex(Options{Interface:wanted},func(o Options)(windowsAdapter,error) {
			seen = o.Interface
			return windowsAdapter{Device:net.Interface{Index:18}},nil
		})
		if seen!=wanted || index!=18 {t.Fatalf("for %q resolved %q index %d",wanted,seen,index)}
	}
	if got := selectedWiFiInterfaceIndex(Options{Interface:"missing"},func(Options)(windowsAdapter,error){
		return windowsAdapter{},fmt.Errorf("no adapter")
	}); got!=0 {t.Fatalf("unknown adapter fell back to index %d",got)}
	items:=[]wifiConnection{{Alias:"Wi-Fi",State:1,SSID:"home"}}
	if c,ok:=chooseWiFiConnection(items,"Ethernet",0);ok {t.Fatalf("non-WLAN request matched %+v",c)}
	if c,ok:=chooseWiFiConnection(items,"auto",0);!ok || c.Alias!="Wi-Fi"{t.Fatalf("auto selection failed: %+v",c)}
}
