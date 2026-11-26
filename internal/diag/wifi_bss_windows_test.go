//go:build windows

package diag

import (
	"encoding/binary"
	"math"
	"testing"
	"unsafe"
)

func TestWLANBSSNativeLayout(t *testing.T) {
	if unsafe.Sizeof(wlanBSSEntry{})!=360 ||
		unsafe.Offsetof(wlanBSSEntry{}.IEOffset)!=352 ||
		unsafe.Offsetof(wlanBSSEntry{}.IESize)!=356 {
		t.Fatalf("invalid Windows WLAN_BSS_ENTRY layout size=%d ie=%d/%d",
			unsafe.Sizeof(wlanBSSEntry{}),unsafe.Offsetof(wlanBSSEntry{}.IEOffset),unsafe.Offsetof(wlanBSSEntry{}.IESize))
	}
}

func TestWLANBSSParseBoundedAndInformationElements(t *testing.T) {
	stride:=int(unsafe.Sizeof(wlanBSSEntry{}))
	raw:=make([]byte,wlanBSSListHeader+stride+7)
	binary.LittleEndian.PutUint32(raw[0:4],uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[4:8],1)
	row:=(*wlanBSSEntry)(unsafe.Pointer(&raw[8]))
	row.SSID.Length=6
	copy(row.SSID.Bytes[:],[]byte("Office"))
	row.BSSID=[6]byte{0xaa,0xbb,0xcc,0xdd,0xee,0xff}
	row.RSSI=-66
	row.CenterFrequencyKHz=5180000
	row.PHYType=10
	row.IEOffset=uint32(stride)
	row.IESize=7
	copy(raw[8+stride:],[]byte{11,5,2,0,204,0,0})
	got,err:=parseWindowsBSSList(raw)
	if err!=nil || len(got)!=1 {t.Fatalf("decode failed %v %+v",err,got)}
	b:=got[0]
	if b.SSID!="Office" || b.BSSID!="aa:bb:cc:dd:ee:ff" || b.Band!="5 GHz" ||
		b.Channel!=36 || b.RSSIDBM!=-66 || b.PHY!="802.11ax" || b.ChannelUtilPercent==nil ||
		math.Abs(*b.ChannelUtilPercent-80)>0.01 {
		t.Fatalf("bad native BSS decode: %+v",b)
	}
	binary.LittleEndian.PutUint32(raw[4:8],9999)
	if _,err:=parseWindowsBSSList(raw);err==nil {t.Fatal("accepted absurd BSS count")}
}

func TestWLANBSSDoesNotReadOutOfBoundsIE(t *testing.T) {
	stride:=int(unsafe.Sizeof(wlanBSSEntry{}))
	raw:=make([]byte,wlanBSSListHeader+stride)
	binary.LittleEndian.PutUint32(raw[0:4],uint32(len(raw)))
	binary.LittleEndian.PutUint32(raw[4:8],1)
	row:=(*wlanBSSEntry)(unsafe.Pointer(&raw[8]))
	row.RSSI=-60
	row.IEOffset=uint32(stride+500)
	row.IESize=100
	got,err:=parseWindowsBSSList(raw)
	if err!=nil || len(got)!=1 || got[0].ChannelUtilPercent!=nil {
		t.Fatalf("invalid IE bounds: %+v %v",got,err)
	}
}

func TestWiFiWindowsPHYMapping(t *testing.T) {
	cases := []struct {
		phy  uint32
		want string
	}{
		{4, "802.11a"},
		{6, "802.11g"},
		{7, "802.11n"},
		{8, "802.11ac"},
		{10, "802.11ax"},
		{11, "802.11be"},
		{999, "unknown"},
	}
	for _, tc := range cases {
		if got := wifiPHYFromWindows(tc.phy); got != tc.want {
			t.Errorf("Native WLAN PHY %d = %q, want %q", tc.phy, got, tc.want)
		}
	}
}
