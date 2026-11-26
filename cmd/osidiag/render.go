package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ivanversluis/osidiag/internal/diag"
)

const (
	colorGreen = "\x1b[32m"
	colorAmber = "\x1b[33m"
	colorRed   = "\x1b[31m"
	colorReset = "\x1b[0m"
)

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb"
}

func statusLabel(s diag.Status, color bool) string {
	label := strings.ToUpper(string(s))
	prefix := ""
	switch s {
	case diag.OK:
		label, prefix = "OK", colorGreen
	case diag.Warn:
		label, prefix = "WARN", colorAmber
	case diag.Fail:
		label, prefix = "FAIL", colorRed
	case diag.Skipped:
		label, prefix = "SKIP", ""
	case diag.Unknown:
		label, prefix = "UNKNOWN", colorAmber
	}
	if color {
		return prefix + label + colorReset
	}
	return label
}

func drawProgress(w io.Writer, completed, total int, current string, color bool) {
	const width = 21
	full := width * completed / total
	bar := strings.Repeat("#", full) + strings.Repeat("-", width-full)
	if color {
		bar = colorGreen + strings.Repeat("#", full) + colorReset + strings.Repeat("-", width-full)
	}
	fmt.Fprintf(w, "\r\x1b[2KOSI scan [%s] %d/%d  %s", bar, completed, total, current)
}

func clearProgress(w io.Writer) { fmt.Fprint(w, "\r\x1b[2K") }

func statusCounts(results []diag.Result) (ok, warn, fail int) {
	for _, r := range results {
		switch r.Status {
		case diag.OK:
			ok++
		case diag.Warn:
			warn++
		case diag.Fail:
			fail++
		}
	}
	return
}

func overall(results []diag.Result) diag.Status {
	_, warn, fail := statusCounts(results)
	if fail != 0 {
		return diag.Fail
	}
	if warn != 0 {
		return diag.Warn
	}
	return diag.OK
}

func renderReport(w io.Writer, report diag.Report, format string, verbose, color bool) {
	fmt.Fprintf(w, "osidiag %s  |  target: %s\n", report.Version, report.Target)
	ok, warn, fail := statusCounts(report.Results)
	skipped := 0
	for _, r := range report.Results { if r.Status == diag.Skipped { skipped++ } }
	fmt.Fprintf(w, "Status: %-5s  Checks: %d/%d OK  (%d warning, %d failure, %d skipped)\n",
		statusLabel(overall(report.Results), color), ok, len(report.Results), warn, fail, skipped)
	if report.Command == "check" {
		bar := strings.Repeat("#", len(report.Results))
		if color {
			bar = colorGreen + bar + colorReset
		}
		fmt.Fprintf(w, "Progress: [%s] 100%% complete\n", bar)
	}
	fmt.Fprintln(w)
	if format == "table" {
		renderOSITable(w, report.Results, color)
	}
	for _, r := range report.Results {
		if format != "table" {
			fmt.Fprintf(w, "L%d %-14s %-10s %s\n", r.Layer, r.Name, statusLabel(r.Status, color), keyResult(r))
		}
		if r.Error != "" {
			fmt.Fprintf(w, "    Detail: %s\n", r.Error)
		}
		if report.Command == "trace" || report.Command == "l3" {
			if tr, ok := r.Data["trace"].(diag.TraceStats); ok {
				renderTrace(w, report.Target, tr, color)
			}
		} else if report.Command == "check" && r.Layer == 3 {
			if tr, ok := r.Data["trace"].(diag.TraceStats); ok {
				fmt.Fprintf(w, "    Route: %d hops to %s (use 'osidiag trace %s' for details)\n", len(tr.Hops), tr.Address, report.Target)
			}
		}
		if report.Command == "dns" {
			if values, ok := r.Data["records"].([]string); ok {
				for _, value := range values {
					fmt.Fprintf(w, "    %s\n", value)
				}
			}
		}
		if verbose {
			renderDetails(w, r)
		}
	}
	fmt.Fprintf(w, "\nAssessment: %s\n", assessment(report))
}

func renderDetails(w io.Writer, r diag.Result) {
	keys := make([]string, 0, len(r.Data))
	for k := range r.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, err := json.MarshalIndent(r.Data[k], "    ", "  ")
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "    %-20s %s\n", k+":", b)
	}
}

func value(r diag.Result, key string) any {
	if r.Data == nil {
		return nil
	}
	return r.Data[key]
}

func keyResult(r diag.Result) string {
	if r.Status == diag.Skipped { return r.Summary }
	switch r.Name {
	case "Physical":
		if iface, ok := value(r, "interface").(string); ok {
			if wifi, ok := value(r, "wifi").(map[string]any); ok {
                if ssid, ok := wifi["ssid"].(string); ok && ssid != "" {
                    bssid, _ := wifi["bssid"].(string)
                    return fmt.Sprintf("%s %s | %v Mbps | SSID %s | BSSID %s | signal %v%%", iface, value(r, "operstate"), value(r, "speed_mbps"), ssid, bssid, wifi["signal_quality_percent"])
                }
				if signal, ok := wifi["signal_dbm"].(int); ok {
					return fmt.Sprintf("%s %s  |  Wi-Fi %d dBm (%v)", iface, value(r, "operstate"), signal, wifi["signal_quality"])
				}
				return fmt.Sprintf("%s %s  |  Wi-Fi signal unavailable", iface, value(r, "operstate"))
			}
			return fmt.Sprintf("%s %s  |  carrier %v  |  %v Mbps", iface, value(r, "operstate"), value(r, "carrier"), value(r, "speed_mbps"))
		}
	case "DataLink":
        if r.Data == nil {return r.Summary}
		iface, _ := value(r, "interface").(string)
		mac, _ := value(r, "local_mac").(string)
		gw, _ := value(r, "default_gateway").(string)
		gwmac, _ := value(r, "gateway_mac").(string)
		line := fmt.Sprintf("%s  local MAC %s  |  %v neighbors", iface, mac, value(r, "total"))
		if gw != "" {
			line += "  |  gateway " + gw
		}
		if gwmac != "" {
			line += " [" + gwmac + "]"
		}
		return line
	case "WiFi":
		if signal, ok := value(r, "signal_dbm").(int); ok {
			return fmt.Sprintf("%s: %d dBm (%v)", value(r, "interface"), signal, value(r, "signal_quality"))
		}
	case "Network":
		cidr, _ := value(r, "local_cidr").(string)
		gw, _ := value(r, "default_gateway").(string)
		iface, _ := value(r, "interface").(string)
		prefix := ""
		if cidr != "" {
			prefix = iface + " " + cidr
		}
		if gw != "" && gw != "unavailable" {
			prefix += "  >  GW " + gw
		}
		if prefix != "" {
			prefix += "  |  "
		}
		if p, ok := value(r, "ping").(diag.EchoStats); ok {
			return prefix + fmt.Sprintf("%s ping %.1f ms, %.0f%% loss (%d/%d)", p.Address, p.AvgMS, p.LossPercent, p.Received, p.Sent)
		}
		if t, ok := value(r, "trace").(diag.TraceStats); ok {
			reached := "destination reached"
			if !t.Reached {
				reached = "destination not confirmed"
			}
			return prefix + fmt.Sprintf("%s  |  %d hops  |  %s", t.Address, len(t.Hops), reached)
		}
	case "Presentation":
		if tlsVersion, ok := value(r, "tls_version").(string); ok {
			return fmt.Sprintf("%s verified  |  certificate expires in %v days", tlsVersion, value(r, "days_until_expiry"))
		}
	case "Application":
		if h, ok := value(r, "http").(diag.Result); ok {
			if d, ok := value(r, "dns").(diag.Result); ok {
				httpSummary := h.Summary
				if h.Data != nil {
					if loc, ok := h.Data["location"].(string); ok && loc != "" {
						httpSummary += " -> " + loc
					}
				}
				return fmt.Sprintf("%s  |  %s", httpSummary, d.Summary)
			}
		}
		if loc, ok := value(r, "location").(string); ok && loc != "" {
			return r.Summary + " -> " + loc
		}
	case "Speed", "Speedtest":
		if mbps, ok := value(r, "download_mbps").(float64); ok {
			return fmt.Sprintf("download %.1f Mbps (%v bytes)  |  %s", mbps, value(r, "bytes_downloaded"), r.Summary)
		}
	}
	return r.Summary
}

func renderTrace(w io.Writer, target string, tr diag.TraceStats, color bool) {
	fmt.Fprintf(w, "    Path to %s (%s)\n", target, tr.Address)
	fmt.Fprintf(w, "    %-4s %-40s %-12s %s\n", "HOP", "IP ADDRESS", "LATENCY", "RESULT")
	for _, hop := range tr.Hops {
		address, samples, timeouts := "*", []float64{}, 0
		reason := "ICMP no reply"
		for _, p := range hop.Probes {
			if p.Responder != "" {
				address = p.Responder
			}
			if p.Timeout {
				timeouts++
			} else {
				samples = append(samples, p.RTTMS)
			}
			if p.Reply != "" && !p.Timeout {
				reason = p.Reply
			}
		}
		latency := "*"
		if len(samples) > 0 {
			var sum float64
			for _, n := range samples {
				sum += n
			}
			latency = fmt.Sprintf("%.1f ms", sum/float64(len(samples)))
		}
		if hop.Reached {
			reason = "destination reached"
		}
		if timeouts == len(hop.Probes) {
			reason = "no ICMP reply (not proof of loss)"
		}
		if timeouts > 0 && timeouts < len(hop.Probes) {
			reason += fmt.Sprintf(" (%d/%d timeouts)", timeouts, len(hop.Probes))
		}
		if color && hop.Reached {
			reason = colorGreen + reason + colorReset
		}
		fmt.Fprintf(w, "    %-4d %-40s %-12s %s\n", hop.TTL, address, latency, reason)
	}
	if !tr.Reached {
		fmt.Fprintln(w, "    Note: Endpoint not confirmed by ICMP; check HTTP/TCP before assuming an outage.")
	} else {
		fmt.Fprintln(w, "    Note: Intermediate * hops may be filtering/rate-limiting ICMP, not dropping traffic.")
	}
}

func assessment(report diag.Report) string {
	if len(report.Results) == 0 {
		return "No diagnostics were performed."
	}
	for _, r := range report.Results {
		if r.Status == diag.Fail {
			switch r.Layer {
			case 1:
				return "Local interface/link issue. Dependent L2-L7 tests were skipped; check adapter state, driver and physical connectivity."
			case 2:
				return "Neighbor discovery failed. Check local subnet, VLAN and gateway."
			case 3:
				return "Target resolution or ICMP probe failed. Verify DNS, route and ICMP access."
			case 6:
				return "TLS validation failed. Inspect certificate trust, hostname and expiration."
			case 7:
				return "Application test failed. Check DNS and remote HTTP service; inspect response details."
			}
			return r.Summary + ". Inspect the failing layer before going further."
		}
	}
	for _, r := range report.Results {
		if r.Status != diag.Warn {
			continue
		}
		switch r.Name {
		case "WiFi":
			if checks, ok := value(r, "wifi_office_checks").([]diag.LinkCheck); ok {
				for _, name := range []string{"wifi_sticky_client","wifi_rssi","wifi_channel_utilization","wifi_cochannel","wifi_band_steering","wifi_tx_retry_ratio","wifi_roaming"} {
					for _, c := range checks {
						if c.Name == name && (c.Status==diag.Warn || c.Status==diag.Fail) && c.Hint!="" {
							return c.Hint
						}
					}
				}
			}
			return "Wi-Fi connection information needs attention; on Windows, check Location privacy settings if SSID/BSSID is unavailable."
		case "DataLink":
			return "No neighbors cached. Generate local traffic and retry; this alone is not a link failure."
		case "Network":
			if strings.Contains(strings.ToLower(r.Error), "raw icmp") || strings.Contains(strings.ToLower(r.Error), "permission") {
				return "ICMP probe needs CAP_NET_RAW. Other layers may still work."
			}
			return "ICMP results are incomplete. If HTTP/TLS work, isolated hop timeouts usually mean filtering or rate limiting."
		case "Presentation":
			return "TLS certificate status needs attention."
		case "Application":
			return "Inspect HTTP/DNS result; a redirect is normal, not an outage."
		case "Speed", "Speedtest":
			return "Speed test is incomplete or below the supplied reference; see measurement details."
		}
	}
	return "No immediate errors detected in the checks performed."
}
