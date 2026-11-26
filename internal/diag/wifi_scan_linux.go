//go:build linux

package diag

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// iw dev IFACE scan dump reads the kernel's existing scan cache. It DOES NOT
// invoke 'iw scan' or 'iw scan trigger'; therefore it avoids active RF probes.
// Cached sightings and BSS Load IEs can be old or absent.
func cachedLinuxScan(name string) ([]WiFiBSS,error) {
	ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
	defer cancel()
	out,err:=exec.CommandContext(ctx,"iw","dev",name,"scan","dump").Output()
	if err!=nil {return nil,fmt.Errorf("iw cached scan unavailable: %w",err)}
	if len(out)>1<<20 {return nil,fmt.Errorf("iw scan cache exceeds 1 MiB output cap")}
	return parseIWScanDump(out),nil
}

func parseIWScanDump(raw []byte) []WiFiBSS {
	bss:=[]WiFiBSS{}
	var item *WiFiBSS
	flush:=func() {
		if item!=nil && item.BSSID!="" {
			bss=append(bss,*item)
		}
	}
	inBSSLoad:=false
	for _,line:=range strings.Split(string(raw),"\n") {
		v:=strings.TrimSpace(line)
		// Only a real BSSID starts a new entry. "BSS Load:" and other
		// "BSS ..." information elements belong to the current AP.
		if strings.HasPrefix(v, "BSS ") {
			parts := strings.Fields(v)
			if len(parts) >= 2 {
				id := strings.SplitN(parts[1], "(", 2)[0]
				if mac, err := net.ParseMAC(id); err == nil && len(mac) == 6 {
					flush()
					inBSSLoad = false
					item = &WiFiBSS{BSSID: mac.String()}
					continue
				}
			}
			// An invalid entry header should not attach subsequent fields
			// to the preceding, valid AP.
			if strings.Contains(v, "(on ") {
				flush()
				inBSSLoad = false
				item = nil
				continue
			}
		}
		if item==nil {continue}
		if v=="BSS Load:" {
			inBSSLoad=true
			continue
		}
		if inBSSLoad && strings.HasPrefix(v,"* ") {
			switch {
			case strings.HasPrefix(v,"* station count:"):
				text:=strings.TrimSpace(strings.TrimPrefix(v,"* station count:"))
				pieces:=strings.Fields(text)
				if len(pieces)>0 {if n,err:=strconv.Atoi(pieces[0]);err==nil && n>=0 && n<=65535 {
					item.StationCount=&n
				}}
			case strings.HasPrefix(v,"* channel utilisation:") || strings.HasPrefix(v,"* channel utilization:"):
				_,val,_:=strings.Cut(v,":")
				val=strings.TrimSpace(val)
				part:=strings.SplitN(val,"/",2)
				if len(part)==2 && strings.TrimSpace(part[1])=="255" {
					if n,err:=strconv.Atoi(strings.TrimSpace(part[0]));err==nil && n>=0 && n<=255 {
						load:=float64(n)*100/255
						item.ChannelUtilPercent=&load
					}
				}
			}
			continue
		}
		if inBSSLoad && v!="" && !strings.HasPrefix(v,"* ") {
			inBSSLoad=false
		}
		// Track the highest advertised BSS PHY generation from cached IEs.
		// It describes the AP, not the client device capabilities.
		lower:=strings.ToLower(v)
		switch {
		case strings.HasPrefix(lower,"eht capabilities"):
			item.PHY="802.11be"
		case strings.HasPrefix(lower,"he capabilities") && item.PHY!="802.11be":
			item.PHY="802.11ax"
		case strings.HasPrefix(lower,"vht capabilities") && item.PHY!="802.11be" && item.PHY!="802.11ax":
			item.PHY="802.11ac"
		case strings.HasPrefix(lower,"ht capabilities") && item.PHY=="":
			item.PHY="802.11n"
		}
		if key,value,ok:=strings.Cut(v,":");ok {
			value=strings.TrimSpace(value)
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "ssid":
				item.SSID=printableSSID(value)
			case "freq":
				if n,ok:=iwFloat(value);ok && n>0 {
					item.FrequencyMHz=int(n)
					item.Band=wifiFrequencyBand(int(n))
					item.Channel=wifiFrequencyChannel(int(n))
				}
			case "signal":
				if n,ok:=iwFloat(value);ok && n>=-110 && n<=-20 {
					item.RSSIDBM=int(n)
				}
			}
		}
		if strings.HasPrefix(strings.ToLower(v),"primary channel:") {
			fields:=strings.Fields(strings.TrimSpace(strings.TrimPrefix(v,"primary channel:")))
			if len(fields)>0 {
				if n,err:=strconv.Atoi(fields[0]);err==nil && n>0 {item.Channel=n}
			}
		}
		if width:=wirelessWidth.FindStringSubmatch(v);len(width)>1 {
			if n,err:=strconv.Atoi(width[1]);err==nil {item.WidthMHz=n}
		}
	}
	flush()
	return bss
}

func linuxStationCounters(name string) (WiFiStationCounters, bool) {
	raw:=passiveIW(name,"station","dump")
	if len(raw)==0 {return WiFiStationCounters{},false}
	v:=parseIWStation(raw)
	var counters WiFiStationCounters
	if n,ok:=v["tx_packets_total"].(uint64);ok {counters.TxPackets=n;counters.HasPackets=true}
	if n,ok:=v["tx_retries_total"].(uint64);ok {counters.TxRetries=n;counters.HasRetries=true}
	if n,ok:=v["tx_failed_total"].(uint64);ok {counters.TxFailed=n;counters.HasFailed=true}
	if n,ok:=v["beacon_loss_total"].(uint64);ok {counters.BeaconLoss=n;counters.HasBeacons=true}
	return counters,true
}

func wifiOfficeLinux(name string, details map[string]any, o Options) (map[string]any,[]LinkCheck) {
	data:=map[string]any{}
	neighbors,err:=cachedLinuxScan(name)
	if err!=nil {data["bss_cache_note"]=err.Error()}
	current:=WiFiBSS{Band:"unknown",PHY:"unknown"}
	if s,ok:=details["ssid"].(string);ok {current.SSID=s}
	if s,ok:=details["bssid"].(string);ok {current.BSSID=s}
	if s,ok:=details["band"].(string);ok {current.Band=s}
	if s,ok:=details["phy_standard"].(string);ok {current.PHY=s}
	if n,ok:=details["frequency_mhz"].(int);ok {current.FrequencyMHz=n}
	if n,ok:=details["channel"].(int);ok {current.Channel=n}
	if n,ok:=details["channel_width_mhz"].(int);ok {current.WidthMHz=n}
	if n,ok:=details["signal_dbm"].(int);ok {current.RSSIDBM=n}
	for _,b:=range neighbors {
		if strings.EqualFold(b.BSSID,current.BSSID) && current.BSSID!="" {
			if current.SSID=="" {current.SSID=b.SSID}
			if current.Channel==0 {current.Channel=b.Channel}
			if current.Band=="unknown" {current.Band=b.Band}
			if current.FrequencyMHz==0 {current.FrequencyMHz=b.FrequencyMHz}
			if current.PHY=="unknown" {current.PHY=b.PHY}
			if current.WidthMHz==0 {current.WidthMHz=b.WidthMHz}
			if !hasWiFiRSSI(current) {current.RSSIDBM=b.RSSIDBM}
			current.ChannelUtilPercent=b.ChannelUtilPercent
			current.StationCount=b.StationCount
			break
		}
	}
	var noise *int
	if n,ok:=details["noise_dbm"].(int);ok && n<=-20 && n>=-110 {noise=&n}
	if noise==nil {
		if n,ok:=parseIWSurveyNoise(passiveIW(name,"survey","dump"),current.FrequencyMHz);ok {
			noise=&n
			data["noise_dbm"]=n
			data["noise_source"]="iw survey dump (passive, frequency-matched)"
		}
	}
	rx,tx:=0.0,0.0
	if n,ok:=details["rx_bitrate_mbps"].(float64);ok {rx=n}
	if n,ok:=details["tx_bitrate_mbps"].(float64);ok {tx=n}
	fields,checks:=officeWiFiAssessment(current,neighbors,noise,rx,tx,o.MinWiFiMbps)
	for k,v:=range fields {data[k]=v}
	groups,count:=compactWiFiGroups(neighbors,o.Limit)
	data["ssid_groups"]=groups
	data["cached_bssids_total"]=count
	if o.WiFiSample<=0 {
		data["roaming_history"]="not sampled (use --wifi-sample 15s)"
		return data,checks
	}
	startCounters,okStart:=linuxStationCounters(name)
	startTime:=time.Now()
	readings:=[]WiFiObservation{linuxAssociationSnapshot(name,0)}
	deadline:=startTime.Add(o.WiFiSample)
	for time.Now().Before(deadline) {
		pause:=2*time.Second
		if remaining:=time.Until(deadline);remaining<pause {pause=remaining}
		if pause<=0 {break}
		time.Sleep(pause)
		readings=append(readings,linuxAssociationSnapshot(name,time.Since(startTime).Milliseconds()))
	}
	obsFields,obsChecks:=assessWiFiObservations(readings)
	for k,v:=range obsFields {data[k]=v}
	checks=append(checks,obsChecks...)
	endCounters,okEnd:=linuxStationCounters(name)
	if okStart && okEnd && obsFields["bssid_changes_observed"]==0 && obsFields["disconnect_transitions_observed"]==0 {
		counterFields,counterChecks:=assessStationCounters(startCounters,endCounters,time.Since(startTime))
		for k,v:=range counterFields {data[k]=v}
		checks=append(checks,counterChecks...)
	} else {
		checks=append(checks,LinkCheck{"wifi_tx_retry_ratio",Unknown,"unknown","nl80211 station counters",
			"Station counters unavailable or association changed during observation; cannot attribute deltas safely."})
	}
	return data,checks
}

func linuxAssociationSnapshot(name string, ms int64) WiFiObservation {
	obs:=WiFiObservation{ElapsedMS:ms}
	link:=passiveIW(name,"link")
	if len(link)==0 {return obs}
	data:=parseIWLink(link)
	obs.Connected,_=data["associated"].(bool)
	obs.BSSID,_=data["bssid"].(string)
	return obs
}


// iw survey dump is read-only. Noise is tied to the actual connected
// frequency; survey records for adjacent channels cannot be substituted.
func parseIWSurveyNoise(raw []byte, mhz int) (int,bool) {
	if mhz<=0 {return 0,false}
	selected:=false
	for _,line:=range strings.Split(string(raw),"\n") {
		line=strings.TrimSpace(line)
		if strings.HasPrefix(line,"frequency:") {
			v:=strings.TrimSpace(strings.TrimPrefix(line,"frequency:"))
			f,ok:=iwFloat(v)
			selected=ok && int(f)==mhz
			continue
		}
		if selected && strings.HasPrefix(line,"noise:") {
			v:=strings.TrimSpace(strings.TrimPrefix(line,"noise:"))
			n,ok:=iwFloat(v)
			if ok && n>=-110 && n<=-20 {return int(n),true}
		}
	}
	return 0,false
}
