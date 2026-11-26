//go:build windows

package diag

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"syscall"
	"unicode/utf8"
    "unicode"
	"unsafe"
)

// Wi-Fi diagnostics use the Windows Native WLAN API (wlanapi.dll). Enumerating
// WLAN interfaces avoids virtual Wi-Fi Direct adapters from the IP adapter list.
// Windows 11 may require location access to reveal SSID/BSSID. No scan occurs.
var (
	wlanAPI            = syscall.NewLazyDLL("wlanapi.dll")
	wlanOpenHandle     = wlanAPI.NewProc("WlanOpenHandle")
	wlanCloseHandle    = wlanAPI.NewProc("WlanCloseHandle")
	wlanEnumInterfaces = wlanAPI.NewProc("WlanEnumInterfaces")
	wlanQueryInterface = wlanAPI.NewProc("WlanQueryInterface")
	wlanFreeMemory     = wlanAPI.NewProc("WlanFreeMemory")
)

type wlanGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}
type wlanInterfaceInfo struct {
	GUID        wlanGUID
	Description [256]uint16
	State       uint32
}
type wlanInterfaceList struct {
	Count uint32
	Index uint32
	First wlanInterfaceInfo
}
type wlanSSID struct {
	Length uint32
	Bytes  [32]byte
}
type wlanAssociation struct {
	SSID     wlanSSID
	BSSType  uint32
	BSSID    [6]byte
	_        [2]byte
	PHYType  uint32
	PHYIndex uint32
	Quality  uint32
	RXRate   uint32
	TXRate   uint32
}
type wlanSecurity struct {
	Enabled uint32
	OneX uint32
	Authentication uint32
	Cipher uint32
}
type wlanConnection struct {
	State       uint32
	Mode        uint32
	ProfileName [256]uint16
	Association wlanAssociation
	Security wlanSecurity
}
type wifiConnection struct {
	Alias       string
	Description string
	GUID        string
	State       uint32
	SSID        string
	BSSID       string
	Quality     uint32
	RxMbps      float64
	TxMbps      float64
	PHYType     uint32
	Channel uint32
	Radio string
	SecurityKnown bool
	SecurityEnabled bool
	Authentication uint32
	Cipher uint32
}

func (g wlanGUID) String() string {
	b := g.Data4
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		g.Data1, g.Data2, g.Data3, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7])
}
func guidNormalized(s string) string { return strings.ToLower(strings.Trim(s, "{} ")) }
func ssidText(s wlanSSID) string {
	n := int(s.Length)
	if n < 0 || n > len(s.Bytes) {
		return ""
	}
	b := s.Bytes[:n]
	if utf8.Valid(b) {
        safe := true
        for _,r := range string(b) {if !unicode.IsPrint(r) {safe=false;break}}
        if safe {return string(b)}
    }
    // Wireless SSIDs are untrusted external bytes: never emit terminal ESC
    // or other control characters into a console or TUI.
    return "hex:" + hex.EncodeToString(b)
}
func wlanMappedAliases() map[string]string {
	aliases := make(map[string]string)
	adapters, err := windowsIPv4Adapters()
	if err != nil {
		return aliases
	}
	for _, a := range adapters {
		n := 0
		for n < len(a.AdapterName) && a.AdapterName[n] != 0 {
			n++
		}
		key := guidNormalized(string(a.AdapterName[:n]))
		alias := interfaceAlias(a.Index)
		if alias != "" && key != "" {
			aliases[key] = alias
		}
	}
	return aliases
}
func wlanConnectionInfo(info wlanInterfaceInfo, h uintptr) (wifiConnection, error) {
	item := wifiConnection{Description: syscall.UTF16ToString(info.Description[:]), GUID: info.GUID.String(), State: info.State}
	var size uint32
	var data unsafe.Pointer
	// wlan_intf_opcode_current_connection = 7.
	code, _, _ := wlanQueryInterface.Call(h, uintptr(unsafe.Pointer(&info.GUID)), 7, 0, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), 0)
	if code != 0 {
		if code == 5 {
			return item, fmt.Errorf("Windows denied Wi-Fi SSID/BSSID access: allow location access under Settings > Privacy & security > Location (Win32 error 5)")
		}
		return item, fmt.Errorf("Wi-Fi connection information unavailable (Win32 error %d)", code)
	}
	if data == nil {
		return item, fmt.Errorf("Windows returned empty Wi-Fi connection data")
	}
	defer wlanFreeMemory.Call(uintptr(data))
	if size < uint32(unsafe.Offsetof(wlanConnection{}.Association)+unsafe.Sizeof(wlanAssociation{})) {
		return item, fmt.Errorf("truncated WLAN connection data (%d bytes)", size)
	}
	c := (*wlanConnection)(data)
	item.State = c.State
	item.SSID = ssidText(c.Association.SSID)
	item.BSSID = net.HardwareAddr(c.Association.BSSID[:]).String()
	item.Quality = c.Association.Quality
	item.PHYType = c.Association.PHYType
	item.RxMbps = float64(c.Association.RXRate) / 1000
	item.TxMbps = float64(c.Association.TXRate) / 1000
	if size >= uint32(unsafe.Offsetof(wlanConnection{}.Security)+unsafe.Sizeof(wlanSecurity{})) {
		item.SecurityKnown = true
		item.SecurityEnabled = c.Security.Enabled != 0
		item.Authentication = c.Security.Authentication
		item.Cipher = c.Security.Cipher
	}
	if channel, err := wlanQueryDWord(h, &info.GUID, 8); err == nil {
		item.Channel = channel
	}
	item.Radio = wlanRadioState(h, &info.GUID)
	return item, nil
}
func nativeWiFiConnections() ([]wifiConnection, error) {
	var negotiated uint32
	var handle uintptr
	code, _, _ := wlanOpenHandle.Call(2, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle)))
	if code != 0 {
		return nil, fmt.Errorf("WlanOpenHandle Win32 error %d", code)
	}
	defer wlanCloseHandle.Call(handle, 0)
	var address unsafe.Pointer
	code, _, _ = wlanEnumInterfaces.Call(handle, 0, uintptr(unsafe.Pointer(&address)))
	if code != 0 {
		return nil, fmt.Errorf("WlanEnumInterfaces Win32 error %d", code)
	}
	if address == nil {
		return nil, fmt.Errorf("no WLAN interfaces returned")
	}
	defer wlanFreeMemory.Call(uintptr(address))
	list := (*wlanInterfaceList)(address)
	if list.Count > 64 {
		return nil, fmt.Errorf("unexpected number of Wi-Fi interfaces: %d", list.Count)
	}
	aliases := wlanMappedAliases()
	results := make([]wifiConnection, 0, int(list.Count))
	stride := unsafe.Sizeof(wlanInterfaceInfo{})
	base := unsafe.Pointer(&list.First)
	for i := uint32(0); i < list.Count; i++ {
		info := *(*wlanInterfaceInfo)(unsafe.Add(base, uintptr(i)*stride))
		item := wifiConnection{GUID: info.GUID.String(), State: info.State, Description: syscall.UTF16ToString(info.Description[:])}
		item.Alias = aliases[guidNormalized(item.GUID)]
		if item.Alias == "" {
			item.Alias = item.Description
		}
		if info.State == 1 {
			// Do not turn SSID permission failures into a generic "no radio".
			connected, err := wlanConnectionInfo(info, handle)
			if err != nil {
				return results, err
			}
			connected.Alias = item.Alias
			item = connected
		}
		results = append(results, item)
	}
	return results, nil
}
func chooseWiFiConnection(connections []wifiConnection, wanted string, defaultIndex int) (wifiConnection, bool) {
	if wanted != "auto" {
		for _, c := range connections {
			if strings.EqualFold(wanted, c.Alias) || strings.EqualFold(wanted, c.Description) || strings.EqualFold(guidNormalized(wanted), c.GUID) {
				return c, true
			}
		}
		// Prefer friendly alias obtained from native IP Helper when an index
		// is supplied by the caller, including virtualized host interfaces.
		if defaultIndex > 0 {
			for _, c := range connections {
				if strings.EqualFold(c.Alias, interfaceAlias(uint32(defaultIndex))) {
					return c, true
				}
			}
		}
		return wifiConnection{}, false
	}
	if defaultIndex > 0 {
		alias := interfaceAlias(uint32(defaultIndex))
		for _, c := range connections {
			if strings.EqualFold(c.Alias, alias) && c.State == 1 {
				return c, true
			}
		}
	}
	for _, c := range connections {
		if c.State == 1 {
			return c, true
		}
	}
	if len(connections) > 0 {
		return connections[0], true
	}
	return wifiConnection{}, false
}
func wifiData(c wifiConnection) map[string]any {
	d := map[string]any{"interface": c.Alias, "description": c.Description, "connected": c.State == 1}
	if c.State == 1 {
		d["ssid"] = c.SSID
		d["bssid"] = c.BSSID
		d["signal_quality_percent"] = c.Quality
		d["rx_rate_mbps"] = c.RxMbps
		d["tx_rate_mbps"] = c.TxMbps
		d["phy_type"] = c.PHYType
		d["radio_state"] = c.Radio
		d["channel"] = "unknown"
		if c.Channel != 0 { d["channel"] = c.Channel }
		security, status := windowsWiFiSecurity(c)
		d["security"] = security
		d["security_status"] = string(status)
		d["note"] = "BSSID identifies the associated access-point radio; signal quality is a Windows estimate, not RSSI in dBm or link throughput. Band and channel width are unknown without BSS frequency data."
	}
	return d
}
// Resolve the adapter the caller actually requested. Using the default-route
// adapter for an explicit selection can falsely attribute another WLAN's SSID.
func selectedWiFiInterfaceIndex(o Options, resolve func(Options) (windowsAdapter, error)) int {
	adapter, err := resolve(o)
	if err != nil { return 0 }
	return adapter.Device.Index
}

func Wireless(o Options) Result {
	connections, err := nativeWiFiConnections()
	if err != nil {
		return result(1, "WiFi", Warn, "Wi-Fi details unavailable", map[string]any{"note": "Windows may require location permission to disclose SSID/BSSID; no active scan is performed."}, err)
	}
	index := 0
	index = selectedWiFiInterfaceIndex(o, winInterface)
	c, ok := chooseWiFiConnection(connections, o.Interface, index)
	if !ok {
		return result(1, "WiFi", Warn, "no matching Wi-Fi adapter", map[string]any{"requested_interface": o.Interface}, nil)
	}
	data := wifiData(c)
	if c.State != 1 {
		return result(1, "WiFi", Warn, c.Alias+" disconnected", data, nil)
	}
	status := OK
	if _, sec := windowsWiFiSecurity(c); sec == Warn { status = Warn }
	if c.Radio == "off" { status = Fail }
	survey, checks := wifiOfficeWindows(c, o)
	for k,v := range survey { data[k]=v }
	status = worstWiFiStatus(status, checks)
	return result(1, "WiFi", status, fmt.Sprintf("%s  SSID %s  |  AP %s  |  signal %d%%", c.Alias, c.SSID, c.BSSID, c.Quality), data, nil)
}
func selectedWiFi(a windowsAdapter, o Options) (map[string]any, error) {
	connected, err := nativeWiFiConnections()
	if err != nil {
		return nil, err
	}
	for _, c := range connected {
		if strings.EqualFold(c.Alias, a.Alias) && c.State == 1 {
			data := wifiData(c)
			survey, _ := wifiOfficeWindows(c, o)
			for k,v := range survey { data[k]=v }
			return data, nil
		}
	}
	return nil, fmt.Errorf("associated Wi-Fi network not available")
}

// Only passive Native WLAN queries are made here; no WlanScan or association
// operation is performed. Location permission can restrict BSS identifiers.
func wlanQueryDWord(h uintptr, guid *wlanGUID, opcode uint32) (uint32, error) {
	var size uint32
	var data unsafe.Pointer
	var valueType uint32
	code, _, _ := wlanQueryInterface.Call(h, uintptr(unsafe.Pointer(guid)), uintptr(opcode), 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&valueType)))
	if code != 0 { return 0, fmt.Errorf("WlanQueryInterface opcode %d: %d", opcode, code) }
	if data == nil { return 0, fmt.Errorf("WlanQueryInterface returned no data") }
	defer wlanFreeMemory.Call(uintptr(data))
	if size < 4 { return 0, fmt.Errorf("WlanQueryInterface DWORD truncated: %d", size) }
	return *(*uint32)(data), nil
}

func wlanRadioState(h uintptr, guid *wlanGUID) string {
	// WLAN_INTF_OPCODE_RADIO_STATE = 4.
	var size uint32
	var data unsafe.Pointer
	var valueType uint32
	code, _, _ := wlanQueryInterface.Call(h, uintptr(unsafe.Pointer(guid)), 4, 0,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&valueType)))
	if code != 0 || data == nil { return "unknown" }
	defer wlanFreeMemory.Call(uintptr(data))
	if size < 4 { return "unknown" }
	n := *(*uint32)(data)
	if n == 0 || n > 64 || uint64(size) < 4+uint64(n)*12 { return "unknown" }
	raw := unsafe.Slice((*byte)(data), int(size))
	for i:=uint32(0);i<n;i++ {
		// WLAN_PHY_RADIO_STATE: PHY index, software state, hardware state.
		off := 4+int(i)*12
		soft := uint32(raw[off+4]) | uint32(raw[off+5])<<8 | uint32(raw[off+6])<<16 | uint32(raw[off+7])<<24
		hard := uint32(raw[off+8]) | uint32(raw[off+9])<<8 | uint32(raw[off+10])<<16 | uint32(raw[off+11])<<24
		if soft == 2 || hard == 2 { return "off" }
		if soft != 1 || hard != 1 { return "unknown" }
	}
	return "on"
}

func windowsWiFiSecurity(c wifiConnection) (string, Status) {
	if !c.SecurityKnown { return "unknown", Unknown }
	if !c.SecurityEnabled || c.Cipher == 0 {
		return "open (unencrypted)", Warn
	}
	switch c.Cipher {
	case 1,5,0x101:
		return "WEP (insecure)", Warn
	case 2:
		return "TKIP (legacy/insecure)", Warn
	}
	switch c.Authentication {
	case 1,2:
		return "802.11 legacy authentication", Warn
	case 3,4:
		return "WPA (legacy)", Warn
	case 6,7:
		return "WPA2/RSNA", OK
	case 8,9,10:
		return "WPA3/OWE", OK
	default:
		return fmt.Sprintf("auth=%d cipher=%d (classification unknown)", c.Authentication, c.Cipher), Unknown
	}
}
