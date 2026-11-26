//go:build windows

package diag

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unsafe"
)

// WLAN_BSS_ENTRY / WLAN_BSS_LIST mirror the Win32 64-bit ABI.
// Information element offsets are relative to the beginning of the entry,
// rather than the BSS_LIST header. Never access driver-returned offsets before
// verifying their bounds.
type wlanBSSEntry struct {
	SSID              wlanSSID
	PHYID             uint32
	BSSID             [6]byte
	_                 [2]byte
	BSSType           uint32
	PHYType           uint32
	RSSI              int32
	Quality           uint32
	InRegDomain       byte
	_                 byte
	BeaconPeriod      uint16
	_                 [4]byte
	Timestamp         uint64
	HostTimestamp     uint64
	Capability        uint16
	_                 [2]byte
	CenterFrequencyKHz uint32
	RateSet           [256]byte
	IEOffset          uint32
	IESize            uint32
}

const (
	wlanBSSListHeader = 8
	maxWlanBSSBytes = 8 << 20
	maxWlanBSSCount = 2048
)

var wlanGetNetworkBssList = wlanAPI.NewProc("WlanGetNetworkBssList")

func parseWlanGUID(s string) (wlanGUID, error) {
	n := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	b, err := hex.DecodeString(n)
	if err != nil || len(b) != 16 { return wlanGUID{}, fmt.Errorf("invalid WLAN interface GUID") }
	var g wlanGUID
	g.Data1 = binary.BigEndian.Uint32(b[:4])
	g.Data2 = binary.BigEndian.Uint16(b[4:6])
	g.Data3 = binary.BigEndian.Uint16(b[6:8])
	copy(g.Data4[:],b[8:])
	return g, nil
}

// wifiPHYFromWindows maps Native WLAN DOT11_PHY_TYPE values.
// Keep this Windows-only helper in a Windows build-tagged file so Linux
// staticcheck does not report its platform-specific use as dead code.
func wifiPHYFromWindows(value uint32) string {
	switch value {
	case 7: return "802.11n"
	case 8: return "802.11ac"
	case 10: return "802.11ax"
	case 11: return "802.11be"
	case 6: return "802.11g"
	case 4: return "802.11a"
	default: return "unknown"
	}
}

func wifiBandOffice(mhz int) string {
	switch {
	case mhz >= 2400 && mhz < 2500: return "2.4 GHz"
	case mhz >= 4900 && mhz < 5925: return "5 GHz"
	case mhz >= 5925 && mhz < 7125: return "6 GHz"
	default: return "unknown"
	}
}

func bssWidthFromIE(raw []byte) int {
	width := 0
	for len(raw)>=2 {
		id,n:=raw[0],int(raw[1])
		raw=raw[2:]
		if len(raw)<n { break }
		switch {
		case id==61 && n>=2:
			if raw[1]&0x04!=0 {width=40} else {width=20}
		case id==192 && n>=3:
			if raw[0]==1 {width=80}
			if raw[0]==2 {width=160}
			// 80+80 is non-contiguous: do not invent a 160 MHz width.
		}
		raw=raw[n:]
	}
	return width
}

func parseWindowsBSSList(raw []byte) ([]WiFiBSS,error) {
	if len(raw)<wlanBSSListHeader || len(raw)>maxWlanBSSBytes {
		return nil,fmt.Errorf("invalid Windows BSS list size")
	}
	total:=binary.LittleEndian.Uint32(raw[0:4])
	count:=binary.LittleEndian.Uint32(raw[4:8])
	stride:=int(unsafe.Sizeof(wlanBSSEntry{}))
	if total < wlanBSSListHeader || int(total)>len(raw) || count>maxWlanBSSCount ||
		uint64(count)>uint64(int(total)-wlanBSSListHeader)/uint64(stride) {
		return nil,fmt.Errorf("invalid Windows BSS count or size")
	}
	raw=raw[:total]
	result:=make([]WiFiBSS,0,int(count))
	for i:=0;i<int(count);i++ {
		start:=wlanBSSListHeader+i*stride
		e:=(*wlanBSSEntry)(unsafe.Pointer(&raw[start]))
		if e.RSSI > -20 || e.RSSI < -110 { continue }
		freq:=int(e.CenterFrequencyKHz/1000)
		row:=WiFiBSS{SSID:ssidText(e.SSID),BSSID:netHardwareAddr(e.BSSID),RSSIDBM:int(e.RSSI),
			FrequencyMHz:freq,Band:wifiBandOffice(freq),Channel:wifiFrequencyChannel(freq),
			PHY:wifiPHYFromWindows(e.PHYType)}
		off,n:=uint64(e.IEOffset),uint64(e.IESize)
		if off>=uint64(stride) && n>0 && off<=uint64(len(raw)-start) &&
			n<=uint64(len(raw)-start)-off && n<=8192 {
			ies:=raw[start+int(off):start+int(off+n)]
			row.ChannelUtilPercent,row.StationCount=parseBSSLoadIE(ies)
			row.WidthMHz=bssWidthFromIE(ies)
		}
		result=append(result,row)
	}
	return result,nil
}

func netHardwareAddr(b [6]byte) string {
	// Avoid passing a stack-array slice from a temporary to another package.
	const hexdigits="0123456789abcdef"
	out:=[17]byte{}
	for i,v:=range b {
		if i>0 {out[i*3-1]=':'}
		out[i*3]=hexdigits[v>>4]
		out[i*3+1]=hexdigits[v&15]
	}
	return string(out[:])
}

func cachedWindowsBSS(c wifiConnection) ([]WiFiBSS,error) {
	guid,err:=parseWlanGUID(c.GUID)
	if err!=nil {return nil,err}
	var negotiated uint32
	var handle uintptr
	code,_,_:=wlanOpenHandle.Call(2,0,uintptr(unsafe.Pointer(&negotiated)),uintptr(unsafe.Pointer(&handle)))
	if code!=0 { return nil,fmt.Errorf("WlanOpenHandle: Win32 error %d",code) }
	defer wlanCloseHandle.Call(handle,0)
	var ptr unsafe.Pointer
	// DOT11_BSS_TYPE_ANY=3; bSecurityEnabled=false means both secured
	// and unsecured networks. No WlanScan is called: this is OS cache only.
	code,_,_ = wlanGetNetworkBssList.Call(handle,uintptr(unsafe.Pointer(&guid)),0,3,0,0,uintptr(unsafe.Pointer(&ptr)))
	if code!=0 {
		if code==5 {return nil,fmt.Errorf("BSS cache unavailable: Windows Location permission required (Win32 5)")}
		return nil,fmt.Errorf("WlanGetNetworkBssList: Win32 error %d",code)
	}
	if ptr==nil {return nil,fmt.Errorf("Windows returned an empty BSS list pointer")}
	defer wlanFreeMemory.Call(uintptr(ptr))
	header:=unsafe.Slice((*byte)(ptr),wlanBSSListHeader)
	size:=binary.LittleEndian.Uint32(header[:4])
	if size<wlanBSSListHeader || size>maxWlanBSSBytes {return nil,fmt.Errorf("Windows BSS list size out of bounds: %d",size)}
	return parseWindowsBSSList(unsafe.Slice((*byte)(ptr),int(size)))
}

func wifiOfficeWindows(c wifiConnection, o Options) (map[string]any, []LinkCheck) {
	data:=map[string]any{}
	if adapter,err:=winInterface(Options{Interface:c.Alias});err==nil && len(adapter.Device.HardwareAddr)>0 {
		data["client_mac"]=adapter.Device.HardwareAddr.String()
		data["client_mac_note"]="Current Wi-Fi interface MAC (may be OS-randomized); search this MAC in Meraki Dashboard."
	}
	neighbors,err:=cachedWindowsBSS(c)
	if err!=nil {
		data["bss_cache_note"]=err.Error()
	}
	current:=WiFiBSS{SSID:c.SSID,BSSID:c.BSSID,PHY:wifiPHYFromWindows(c.PHYType),
		Channel:int(c.Channel),Band:"unknown"}
	for _,b:=range neighbors {
		if strings.EqualFold(b.BSSID,c.BSSID) {
			current=b
			break
		}
	}
	if current.Band=="unknown" && current.Channel!=0 {
		data["band_note"]="Connected channel alone cannot uniquely establish the 2.4/5/6 GHz band."
	}
	groups,total:=compactWiFiGroups(neighbors,o.Limit)
	data["ssid_groups"]=groups
	data["cached_bssids_total"]=total
	fields,checks:=officeWiFiAssessment(current,neighbors,nil,c.RxMbps,c.TxMbps,o.MinWiFiMbps)
	for k,v:=range fields {data[k]=v}
	// WLAN signal quality (%) is *not* RSSI. Only per-BSSID RSSI from the
	// Native WLAN BSS cache is suitable for -67/-75 dBm thresholds.
	if hasWiFiRSSI(current) {data["signal_dbm"]=current.RSSIDBM}
	if o.WiFiSample>0 {
		samples:=[]WiFiObservation{{Connected:true,BSSID:c.BSSID,ElapsedMS:0}}
		start:=time.Now()
		deadline:=start.Add(o.WiFiSample)
		for time.Now().Before(deadline) {
			next:=2*time.Second
			if remaining:=time.Until(deadline);remaining<next {next=remaining}
			if next<=0 {break}
			time.Sleep(next)
			all,err:=nativeWiFiConnections()
			if err!=nil {break}
			selected,ok:=chooseWiFiConnection(all,c.Alias,0)
			if !ok {break}
			samples=append(samples,WiFiObservation{ElapsedMS:time.Since(start).Milliseconds(),
				Connected:selected.State==1,BSSID:selected.BSSID})
		}
		fields,observations:=assessWiFiObservations(samples)
		for k,v:=range fields {data[k]=v}
		checks=append(checks,observations...)
	} else {
		data["roaming_history"]="not sampled (use --wifi-sample 15s)"
	}
	data["wifi_office_checks"]=checks
	return data,checks
}
