package diag

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
)

type Result struct {
	Layer      int            `json:"layer"`
	Name       string         `json:"name"`
	Status     Status         `json:"status"`
	Summary    string         `json:"summary"`
	Data       map[string]any `json:"data,omitempty"`
	Error      string         `json:"error,omitempty"`
	DurationMS int64          `json:"duration_ms"`
}
type Report struct {
	Version   string   `json:"version"`
	Timestamp string   `json:"timestamp"`
	Command   string   `json:"command"`
	Target    string   `json:"target"`
	Results   []Result `json:"results"`
}
type Options struct {
	Target, Interface, Family, URL, DNSType, DNSServer string
	DownloadURL                                        string
	SNI, ConnectIP                                     string
	CompareSNI, GatewayProbe, LLDP                    bool
	MaxBytes                                           int64
	ExpectedMbps, MinLinkMbps, MinWiFiMbps             float64
	Port, Count, Hops, Probes, Limit                   int
	Timeout, LinkSample, WiFiSample                    time.Duration
}
type Task func(Options) Result

func Measure(fn Task, o Options) Result {
	start := time.Now()
	r := fn(o)
	r.DurationMS = time.Since(start).Milliseconds()
	return r
}
func result(layer int, name string, status Status, summary string, data map[string]any, err error) Result {
	r := Result{Layer: layer, Name: name, Status: status, Summary: summary, Data: data}
	if err != nil {
		r.Error = err.Error()
	}
	return r
}
func (o Options) Validate() error {
	if strings.TrimSpace(o.Target) == "" {
		return errors.New("--target must not be empty")
	}
	if strings.ContainsAny(o.Target, " /\\") {
		return errors.New("--target must be hostname or IP, not URL")
	}
	if o.Family != "auto" && o.Family != "4" && o.Family != "6" {
		return errors.New("--family must be auto, 4 or 6")
	}
	if o.Port < 1 || o.Port > 65535 {
		return errors.New("--port must be 1-65535")
	}
	if o.Count < 1 || o.Count > 50 || o.Hops < 1 || o.Hops > 255 || o.Probes < 1 || o.Probes > 10 {
		return errors.New("--count 1-50, --hops 1-255, --probes 1-10 required")
	}
	if o.Timeout < 10*time.Millisecond || o.Timeout > 30*time.Second {
		return errors.New("--timeout must be 10ms-30s")
	}
	if o.Limit < 1 || o.Limit > 5000 {
		return errors.New("--limit must be 1-5000")
	}
	if o.ConnectIP != "" && net.ParseIP(o.ConnectIP) == nil {
		return errors.New("--connect-ip must be a valid IPv4 or IPv6 address")
	}
	if o.SNI != "" && o.SNI != "none" {
		if net.ParseIP(o.SNI) != nil || strings.ContainsAny(o.SNI, " /\\:") || strings.HasPrefix(o.SNI, ".") || strings.HasSuffix(o.SNI, ".") {
			return errors.New("--sni must be a DNS hostname or none")
		}
	}
	if o.CompareSNI && o.SNI == "none" {
		return errors.New("--compare-sni needs a named SNI; omit --sni none")
	}
	if o.LinkSample < 0 || o.LinkSample > 10*time.Second {
		return errors.New("--link-sample must be 0s to 10s")
	}
	if o.WiFiSample != 0 && (o.WiFiSample < 10*time.Second || o.WiFiSample > 30*time.Second) {
		return errors.New("--wifi-sample must be 0s or between 10s and 30s")
	}
	if o.MinWiFiMbps < 0 || o.MinWiFiMbps > 100000 {
		return errors.New("--min-wifi-mbps must be between 0 and 100000")
	}
	if o.MinLinkMbps < 0 || o.MinLinkMbps > 100000 {
		return errors.New("--min-link-mbps must be 0 to 100000")
	}
	if o.Interface == "" {
		return errors.New("--iface cannot be empty")
	}
	switch strings.ToUpper(o.DNSType) {
	case "A", "AAAA", "MX", "NS", "CNAME", "TXT", "PTR", "SRV":
	default:
		return fmt.Errorf("unsupported DNS record type: %s", o.DNSType)
	}
	if o.DNSServer != "" && net.ParseIP(o.DNSServer) == nil {
		host, port, err := net.SplitHostPort(o.DNSServer)
		if err != nil || net.ParseIP(host) == nil || port == "" {
			return errors.New("--dns-server must be IP or IP:port")
		}
	}
	return nil
}
