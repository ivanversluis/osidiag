// osidiag provides OSI-layer diagnostics on Linux and Windows.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ivanversluis/osidiag/internal/diag"
)

var version = "0.4.0" // Overridden by the tagged release build via -ldflags.

func usage(w io.Writer) {
	fmt.Fprintf(w, `osidiag %s - OSI network diagnostics for Linux and Windows 11

Usage: osidiag <command> [target] [flags]

ASSESSMENTS (end-to-end or adapter-focused)
  check       OSI L1-L7 assessment (default: example.com)
  wifi        Wi-Fi association: SSID, AP BSSID, signal quality (Windows/Linux)
  speedtest   Explicit service reachability and bounded HTTP download sample
              ("speed" remains an alias)

OSI LAYER DIAGNOSTICS
  l1          Physical link, adapter, speed, Wi-Fi details when connected
  l2          ARP/neighbor cache, gateway MAC, passive DHCP lease
  dhcp        Show passive DHCP lease/server metadata
  l3          IP addressing, route and ICMP reachability
  l4          Direct target TCP connection + local listening TCP/UDP endpoints
  l5          Local TCP connection states (OSI session-layer approximation)
  l6          TLS handshake and certificate validity
  l7          HTTP response and DNS lookup

INDIVIDUAL TESTS
  ping        ICMP echo probes
  trace       Hop-by-hop traceroute (may take time)
  tls         TLS diagnostics (alias for l6)
  http        HTTP HEAD; use -v for response headers (cookies redacted)
  dns         DNS record lookup (A, AAAA, MX, NS, CNAME, TXT, PTR, SRV)

COMMON OPTIONS
  --target hostname             Default example.com; positional target also works
  --iface name                  Adapter name, Windows friendly alias, index, or auto
  --family auto|4|6             IP family for ICMP
  --port number                 Target TCP/TLS port (default 443)
  --sni hostname|none           Override TLS SNI or explicitly omit
  --connect-ip address          Pin TLS destination IP; verify hostname
  --compare-sni                 Compare named and no-SNI TLS handshakes
  --timeout duration            Per-operation timeout (default 1s)
  -o, --output table|text|json|tui
  -v, --verbose                 Include structured details (including HTTP headers)
  --json                        Alias for --output json
  --no-color, --no-progress     Disable terminal decoration
  --strict                      Exit nonzero for warnings too
  --limit number                Max neighbors/sockets shown (default 30)
  --link-sample duration         L1 counter sample window (default 5s; 0s disables)
  --min-link-mbps number         Warn if wired negotiated speed is lower (default 0: unset)
  --wifi-sample duration         Observe Wi-Fi roaming/retries for 10-30s (default 0s)
  --min-wifi-mbps number         Optional Wi-Fi PHY rate expectation (default 0: unset)
  --gateway-probe                Opt-in L3 ICMP echo RTT to selected L2 gateway
  --lldp                         Opt-in read-only local LLDP neighbor metadata

SPECIALIZED OPTIONS
  --url url                     HTTP URL (or speedtest service URL)
  --dns-type type               DNS record type (default A)
  --dns-server addr             DNS resolver IP[:port]
  --count number                Ping probes (default 3)
  --hops number                 Traceroute hops (default 12)
  --probes number               Traceroute probes per hop (default 1)
  --download-url url           Independent HTTP payload URL
  --max-bytes number           HTTP download cap (default 8 MiB)
  --expected-mbps number       Optional expected HTTP sample throughput
  --watch                      Repeat bounded downloads until interrupted
  --once                       Download once; avoid interactive speed monitor
  --samples number             Max samples in monitor (0 means until stopped)
  --pause duration             Pause between samples (default 750ms)

Examples:
  osidiag check example.com
  osidiag check example.com --output tui
  osidiag wifi --wifi-sample 15s -v
  osidiag l2 --iface "Wi-Fi" --gateway-probe -v
  osidiag dhcp --iface "Wi-Fi" -v
  osidiag http example.com -v
  osidiag tls app.example.com --connect-ip 203.0.113.10 --compare-sni -v
  osidiag trace example.com --hops 20
  osidiag speedtest --url https://example.com/
  osidiag speedtest --download-url 'https://speed.cloudflare.com/__down?bytes=8388608' --once

Notes: Default-route selection is a heuristic, not per-target policy routing.
       HTTP download sampling uses one stream; upload speed is not measured.
       Linux raw ICMP needs CAP_NET_RAW. WSL2 does not expose Windows radio details.
`, version)
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int { return execute(args, os.Stdout, os.Stderr) }

func tasks(command string) []diag.Task {
	all := []diag.Task{diag.Physical, diag.Neighbors, diag.Network, diag.Transport, diag.Sessions, diag.Presentation, diag.Application}
	switch command {
	case "check":
		return all
	case "l1":
		return all[:1]
	case "wifi":
		return []diag.Task{diag.Wireless}
	case "l2":
		return all[1:2]
	case "dhcp":
		return []diag.Task{diag.DHCPOnly}
	case "l3":
		return all[2:3]
	case "l4":
		return all[3:4]
	case "l5":
		return all[4:5]
	case "l6", "tls":
		return all[5:6]
	case "l7":
		return all[6:7]
	case "ping":
		return []diag.Task{diag.PingOnly}
	case "trace":
		return []diag.Task{diag.TraceOnly}
	case "http":
		return []diag.Task{diag.HTTPOnly}
	case "dns":
		return []diag.Task{diag.DNSOnly}
	case "speed", "speedtest":
		return []diag.Task{diag.SpeedOnly}
	default:
		return nil
	}
}

type cliSettings struct {
	opts       diag.Options
	format     string
	verbose    bool
	noColor    bool
	noProgress bool
	strict     bool
	watch      bool
	once       bool
	samples    int
	pause      time.Duration
}

func isSpeedCommand(command string) bool { return command == "speed" || command == "speedtest" }

func parseCLI(command string, args []string) (cliSettings, error) {
	cfg := cliSettings{}
	o := &cfg.opts
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.Target, "target", "example.com", "hostname or IP")
	fs.StringVar(&o.Interface, "iface", "auto", "interface")
	fs.StringVar(&o.Family, "family", "auto", "IP family")
	fs.IntVar(&o.Port, "port", 443, "TLS port")
	fs.StringVar(&o.SNI, "sni", "", "TLS server name or none")
	fs.StringVar(&o.ConnectIP, "connect-ip", "", "TLS destination IP")
	fs.BoolVar(&o.CompareSNI, "compare-sni", false, "compare TLS handshakes with/without SNI")
	fs.StringVar(&o.URL, "url", "", "HTTP URL")
	fs.StringVar(&o.DNSType, "dns-type", "A", "DNS record type")
	fs.StringVar(&o.DNSServer, "dns-server", "", "DNS resolver")
	fs.IntVar(&o.Count, "count", 3, "ICMP count")
	fs.IntVar(&o.Hops, "hops", 12, "traceroute hops")
	fs.IntVar(&o.Probes, "probes", 1, "probes per hop")
	fs.DurationVar(&o.Timeout, "timeout", time.Second, "timeout")
	fs.IntVar(&o.Limit, "limit", 30, "max detail rows")
	fs.StringVar(&cfg.format, "output", "text", "text|table|json")
	fs.StringVar(&cfg.format, "o", "text", "output format")
	fs.BoolVar(&cfg.verbose, "v", false, "verbose")
	fs.BoolVar(&cfg.verbose, "verbose", false, "verbose")
	fs.BoolVar(&cfg.noColor, "no-color", false, "no ANSI color")
	fs.BoolVar(&cfg.noProgress, "no-progress", false, "no live progress")
	fs.BoolVar(&cfg.strict, "strict", false, "warnings exit nonzero")
	fs.BoolVar(&cfg.watch, "watch", false, "continuous downloads")
	fs.BoolVar(&cfg.once, "once", false, "single download")
	fs.IntVar(&cfg.samples, "samples", 0, "maximum samples (0 unlimited)")
	fs.DurationVar(&cfg.pause, "pause", 750*time.Millisecond, "pause between download samples")
	jsonAlias := fs.Bool("json", false, "JSON output")
	fs.StringVar(&o.DownloadURL, "download-url", "", "download test URL")
	fs.Int64Var(&o.MaxBytes, "max-bytes", 8<<20, "maximum download bytes")
	fs.Float64Var(&o.ExpectedMbps, "expected-mbps", 0, "optional expected throughput")
	fs.DurationVar(&o.LinkSample, "link-sample", 5*time.Second, "L1 error counter sampling period (0 disables)")
	fs.Float64Var(&o.MinLinkMbps, "min-link-mbps", 0, "minimum expected wired link speed in Mbps")
	fs.DurationVar(&o.WiFiSample, "wifi-sample", 0, "observe Wi-Fi association/retry changes over 10-30s (0 disables)")
	fs.Float64Var(&o.MinWiFiMbps, "min-wifi-mbps", 0, "optional minimum negotiated Wi-Fi RX/TX PHY Mbps")
	fs.BoolVar(&o.GatewayProbe, "gateway-probe", false, "opt-in ICMP RTT to default gateway (included as L3 evidence in L2)")
	fs.BoolVar(&o.LLDP, "lldp", false, "opt-in read-only LLDP neighbor inventory")
	// Go's flag parser stops at the first positional argument. Accept both
	// "dns nu.nl --dns-type MX" and "dns --dns-type MX nu.nl".
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		args = append(append([]string{}, args[1:]...), args[0])
	}
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if *jsonAlias {
		if cfg.format != "text" && cfg.format != "json" {
			return cfg, errors.New("--json conflicts with --output table or tui")
		}
		cfg.format = "json"
	}
	switch cfg.format {
	case "text", "table", "json", "tui":
	default:
		return cfg, fmt.Errorf("unsupported --output %q (use table, text, json or tui)", cfg.format)
	}
	if fs.NArg() > 1 {
		return cfg, fmt.Errorf("expected at most one target, got %q", fs.Args())
	}
	var targetExplicit, portExplicit, timeoutExplicit, outputExplicit bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "target" {
			targetExplicit = true
		}
		if f.Name == "port" {
			portExplicit = true
		}
		if f.Name == "timeout" {
			timeoutExplicit = true
		}
		if f.Name == "output" || f.Name == "o" {
			outputExplicit = true
		}
	})
	if command == "check" && !outputExplicit && !*jsonAlias {
		cfg.format = "table"
	}
	if fs.NArg() == 1 {
		if targetExplicit {
			return cfg, errors.New("use either a positional target or --target, not both")
		}
		o.Target = fs.Arg(0)
		targetExplicit = true
	}
	// Explicit URL overrides the placeholder target for every command, including
	// "trace --url host", while retaining the URL for HTTP requests.
	if o.URL != "" {
		normalized, host, port, err := normalizeTarget(o.URL)
		if err != nil {
			return cfg, err
		}
		if targetExplicit && o.Target != host {
			return cfg, errors.New("--url and --target specify different hosts")
		}
		o.URL, o.Target = normalized, host
		if !portExplicit && port != 0 {
			o.Port = port
		}
	} else if targetExplicit {
		normalized, host, port, err := normalizeTarget(o.Target)
		if err != nil {
			return cfg, err
		}
		o.Target = host
		if strings.Contains(normalized, "://") && strings.Contains(fs.Arg(0), "://") {
			o.URL = normalized
		}
		if !portExplicit && port != 0 {
			o.Port = port
		}
	}
	// SNI options affect only TLS diagnostics; do not silently accept them elsewhere.
	if command != "tls" && command != "l6" && command != "check" && (o.SNI != "" || o.ConnectIP != "" || o.CompareSNI) {
		return cfg, errors.New("SNI flags require tls, l6 or check")
	}
	if (o.WiFiSample > 0 || o.MinWiFiMbps > 0) && command != "wifi" && command != "l1" && command != "check" {
		return cfg, errors.New("--wifi-sample and --min-wifi-mbps require wifi, l1 or check")
	}
	if (o.GatewayProbe || o.LLDP) && command != "l2" && command != "check" {
		return cfg, errors.New("--gateway-probe and --lldp require l2 or check")
	}
	if isSpeedCommand(command) {
		if o.URL == "" {
			if targetExplicit {
				o.URL = "https://" + net.JoinHostPort(o.Target, "443") + "/"
			} else if o.DownloadURL != "" {
				download, err := url.Parse(o.DownloadURL)
				if err != nil || (download.Scheme != "http" && download.Scheme != "https") || download.Hostname() == "" || download.User != nil {
					return cfg, errors.New("--download-url must be a valid HTTP(S) URL without credentials")
				}
				o.Target = download.Hostname()
			} else {
				return cfg, errors.New("speedtest requires an explicit --url, target, or --download-url; no remote service is selected by default")
			}
		}
		if !timeoutExplicit {
			o.Timeout = 10 * time.Second
		}
	}
	if o.MaxBytes < 256<<10 || o.MaxBytes > 128<<20 {
		return cfg, errors.New("--max-bytes must be between 262144 (256 KiB) and 134217728 (128 MiB)")
	}
	if o.ExpectedMbps < 0 || o.ExpectedMbps > 100000 {
		return cfg, errors.New("--expected-mbps must be between 0 and 100000")
	}
	if cfg.samples < 0 || cfg.samples > 100000 {
		return cfg, errors.New("--samples must be between 0 and 100000")
	}
	if cfg.pause < 0 || cfg.pause > time.Minute {
		return cfg, errors.New("--pause must be between 0s and 1m")
	}
	if cfg.once && (cfg.watch || cfg.samples > 0) {
		return cfg, errors.New("--once conflicts with --watch or --samples")
	}
	if !isSpeedCommand(command) && (o.DownloadURL != "" || o.ExpectedMbps > 0 || cfg.once || cfg.watch || cfg.samples > 0 || cfg.pause != 750*time.Millisecond) {
		return cfg, errors.New("speed flags are only valid with the speed command")
	}
	if isSpeedCommand(command) && (cfg.watch || cfg.samples > 0) && o.DownloadURL == "" {
		return cfg, errors.New("continuous speed tests require --download-url")
	}
	if isSpeedCommand(command) && cfg.format == "json" && (cfg.watch || cfg.samples > 0) {
		return cfg, errors.New("--output json supports single measurements only; use --once or omit --watch")
	}
	if err := o.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// normalizeTarget accepts a hostname, IP, hostname:port or an HTTP(S) URL.
// A bare hostname is normalized to an https URL for --url usage.
func normalizeTarget(input string) (normalized, host string, port int, err error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return "", "", 0, errors.New("target cannot be empty")
	}
	// Raw IPv6 addresses must be bracketed before URL parsing.
	if ip := net.ParseIP(raw); ip != nil {
		return "https://" + net.JoinHostPort(ip.String(), "443"), ip.String(), 0, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", 0, err
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		return "", "", 0, errors.New("target must be a hostname, IP or http(s) URL without credentials")
	}
	host = u.Hostname()
	if strings.ContainsAny(host, " /\\") {
		return "", "", 0, errors.New("invalid hostname")
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", "", 0, errors.New("invalid URL port")
		}
	}
	if u.Fragment != "" {
		u.Fragment = ""
	}
	return u.String(), host, port, nil
}

func execute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "-version") {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage(stdout)
		return 0
	}
	command := strings.ToLower(args[0])
	if command == "speed" {
		command = "speedtest"
	}
	allTasks := tasks(command)
	if allTasks == nil {
		fmt.Fprintf(stderr, "unknown command: %s\n", command)
		usage(stderr)
		return 2
	}
	cfg, err := parseCLI(command, args[1:])
	if err != nil {
		fmt.Fprintf(stderr, "osidiag: %v\n", err)
		return 2
	}
	if isSpeedCommand(command) && cfg.opts.DownloadURL != "" && !cfg.once && cfg.format != "json" &&
		(cfg.watch || cfg.samples > 0 || (isTerminal(stdout) && isTerminal(os.Stdin))) {
		return runSpeedMonitor(cfg, stdout, stderr)
	}
	if cfg.format == "tui" {
		return runCheckTUI(command, cfg, allTasks, stdout, stderr)
	}
	report := diag.Report{Version: version, Timestamp: time.Now().UTC().Format(time.RFC3339), Command: command, Target: cfg.opts.Target}
	interactive := isTerminal(stderr) && cfg.format != "json" && !cfg.noProgress && command == "check"
	colors := isTerminal(stdout) && !cfg.noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	l1Failed := false
	for i, fn := range allTasks {
		if interactive {
			drawProgress(stderr, i, len(allTasks), fmt.Sprintf("L%d %s", i+1, layerName(i)), colors)
		}
		r := executeLayer(command, i, l1Failed, fn, cfg.opts)
		if i == 0 && r.Status == diag.Fail {
			l1Failed = true
		}
		report.Results = append(report.Results, r)
	}
	if interactive {
		clearProgress(stderr)
	}
	if cfg.format == "json" {
		if err := json.NewEncoder(stdout).Encode(report); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	} else {
		renderReport(stdout, report, cfg.format, cfg.verbose, colors)
	}
	for _, r := range report.Results {
		if r.Status == diag.Fail || (cfg.strict && r.Status == diag.Warn) {
			return 1
		}
	}
	return 0
}

func layerName(i int) string {
	return [...]string{"Physical", "DataLink", "Network", "Transport", "Session", "Presentation", "Application"}[i]
}
