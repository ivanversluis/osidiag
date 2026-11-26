//go:build linux

package diag

import (
	"math"
	"testing"
)

func TestCachedIWScanParsesSameSSIDAndBSSLoad(t *testing.T) {
	raw:=[]byte("BSS aa:bb:cc:dd:ee:01(on wlan0)\n" +
		"\tfreq: 5180\n\tsignal: -75.00 dBm\n\tSSID: Meraki-Office\n" +
		"\tBSS Load:\n\t\t* station count: 22\n\t\t* channel utilisation: 204/255\n" +
		"BSS aa:bb:cc:dd:ee:02(on wlan0)\n" +
		"\tfreq: 2412\n\tsignal: -60.00 dBm\n\tSSID: Meraki-Office\n")
	b:=parseIWScanDump(raw)
	if len(b)!=2 || b[0].SSID!="Meraki-Office" || b[1].SSID!="Meraki-Office" {
		t.Fatalf("missing same-SSID APs: %+v",b)
	}
	if b[0].Channel!=36 || b[0].RSSIDBM!=-75 || b[1].Channel!=1 || b[1].Band!="2.4 GHz" {
		t.Fatalf("wrong BSS frequencies: %+v",b)
	}
	if b[0].StationCount==nil || *b[0].StationCount!=22 || b[0].ChannelUtilPercent==nil ||
		math.Abs(*b[0].ChannelUtilPercent-80)>0.01 {
		t.Fatalf("BSS Load missing: %+v",b[0])
	}
}

func TestCachedIWScanHandlesMalformedAndEscapes(t *testing.T) {
	raw:=[]byte("BSS \nBSS notamac (on wlan0)\nSSID: ignore\n"+
		"BSS aa:bb:cc:dd:ee:03(on wlan0)\n\tSSID: Office\x1b[31m\n" +
		"\tBSS Load:\n\t\t* station count: \n\t\t* channel utilisation: 400/255\n")
	b:=parseIWScanDump(raw)
	if len(b)!=1 || b[0].SSID!="hex:4f66666963651b5b33316d" || b[0].StationCount!=nil ||
		b[0].ChannelUtilPercent!=nil {
		t.Fatalf("unsafe or malformed cached scan: %+v",b)
	}
}

func TestCachedIWPHYAndSurveyNoise(t *testing.T) {
	raw:=[]byte("BSS aa:bb:cc:dd:ee:ff(on wlan0)\n" +
		"\tfreq: 5180\n\tSSID: Office\n\tHT capabilities:\n\tVHT capabilities:\n\tHE capabilities:\n")
	b:=parseIWScanDump(raw)
	if len(b)!=1 || b[0].PHY!="802.11ax" {t.Fatalf("highest advertised PHY absent: %+v",b)}
	survey:=[]byte("frequency: 2412 MHz\nnoise: -90 dBm\n"+
		"frequency: 5180 MHz [in use]\nnoise: -95 dBm\n")
	if noise,ok:=parseIWSurveyNoise(survey,5180);!ok || noise!=-95 {
		t.Fatalf("noise wrong: %d %v",noise,ok)
	}
	if _,ok:=parseIWSurveyNoise(survey,5200);ok {t.Fatal("unmatched channel noise incorrectly reused")}
}

func TestCachedIWScanBSSSubsectionsNotHeaders(t *testing.T) {
	raw := []byte("BSS aa:bb:cc:dd:ee:01(on wlan0)\n" +
		"\tSSID: Meraki-Office\n" +
		"\tBSS Color: 7\n" +
		"BSS Load:\n" + // Even an unindented IE must not reset the AP.
		"\t\t* station count: 11\n" +
		"\t\t* channel utilization: 128/255\n" +
		"BSS invalid(on wlan0)\n" + // Bad header must not inherit the previous AP.
		"\tSSID: should-not-appear\n" +
		"BSS aa:bb:cc:dd:ee:02(on wlan0)\n" +
		"\tSSID: Meraki-Office\n")
	found := parseIWScanDump(raw)
	if len(found) != 2 {
		t.Fatalf("expected two real BSSIDs, got %+v", found)
	}
	if found[0].SSID != "Meraki-Office" || found[0].BSSID != "aa:bb:cc:dd:ee:01" ||
		found[0].StationCount == nil || *found[0].StationCount != 11 ||
		found[0].ChannelUtilPercent == nil ||
		math.Abs(*found[0].ChannelUtilPercent-128*100.0/255) > 0.01 {
		t.Fatalf("BSS subsections were misparsed: %+v", found[0])
	}
	if found[1].SSID != "Meraki-Office" || found[1].BSSID != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("invalid BSS header leaked fields into next AP: %+v", found[1])
	}
}
