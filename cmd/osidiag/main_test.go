package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ivanversluis/osidiag/internal/diag"
)

func TestPositionalTargets(t *testing.T) {
	cases := []struct {
		command         string
		args            []string
		target, address string
	}{
		{"dns", []string{"nu.nl"}, "nu.nl", ""},
		{"dns", []string{"nu.nl", "--dns-type", "MX"}, "nu.nl", ""},
		{"trace", []string{"--url", "example.com"}, "example.com", "https://example.com"},
		{"trace", []string{"example.com"}, "example.com", ""},
		{"http", []string{"--url", "https://redirect.example"}, "redirect.example", "https://redirect.example"},
		{"http", []string{"https://redirect.example"}, "redirect.example", "https://redirect.example"},
		{"check", []string{"--target", "example.com"}, "example.com", ""},
		{"speed", []string{"--url", "https://example.com/"}, "example.com", "https://example.com/"},
	}
	for _, tc := range cases {
		t.Run(tc.command+"-"+strings.Join(tc.args, "-"), func(t *testing.T) {
			cfg, err := parseCLI(tc.command, tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.opts.Target != tc.target || cfg.opts.URL != tc.address {
				t.Fatalf("got target=%q url=%q, want target=%q url=%q", cfg.opts.Target, cfg.opts.URL, tc.target, tc.address)
			}
			if tc.command == "dns" && len(tc.args) > 1 && cfg.opts.DNSType != "MX" {
				t.Errorf("dns type not parsed: %s", cfg.opts.DNSType)
			}
		})
	}
}

func TestInvalidCLIOptions(t *testing.T) {
	for _, args := range [][]string{
		{"--output", "yaml"}, {"--json", "--output", "table"},
		{"nu.nl", "example.com"}, {"--target", "nu.nl", "example.com"},
		{"--max-bytes", "123"}, {"--expected-mbps", "-1"},
		{"--url", "ftp://example.com"}, {"--url", "https://a.test", "--target", "b.test"},
	} {
		if _, err := parseCLI("dns", args); err == nil {
			t.Errorf("accepted invalid flags %q", args)
		}
	}
}

func TestJSONOutputHasNoProgressOrANSI(t *testing.T) {
	var out, errs bytes.Buffer
	if exit := execute([]string{"dns", "localhost", "--output", "json"}, &out, &errs); exit != 0 {
		t.Fatalf("exit %d stderr=%s", exit, errs.String())
	}
	var result diag.Report
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Target != "localhost" || len(result.Results) != 1 {
		t.Fatalf("report: %+v", result)
	}
	if strings.Contains(out.String(), "\x1b[") || strings.Contains(out.String(), "Progress:") {
		t.Fatal("non-JSON content in JSON mode")
	}
}

func TestTraceRenderShowsHopIPsAndLossNote(t *testing.T) {
	route := diag.TraceStats{Address: "203.0.113.9", Reached: true, Hops: []diag.TraceHop{
		{TTL: 1, Probes: []diag.Probe{{Responder: "192.0.2.1", Reply: "time-exceeded", RTTMS: 1.25}}},
		{TTL: 2, Probes: []diag.Probe{{Reply: "timeout", Timeout: true}}},
		{TTL: 3, Reached: true, Probes: []diag.Probe{{Responder: "203.0.113.9", Reply: "echo-reply", RTTMS: 12.6, Reached: true}}},
	}}
	r := diag.Report{Version: "0.2.0", Target: "example.net", Command: "trace",
		Results: []diag.Result{{Layer: 3, Name: "Network", Status: diag.OK, Data: map[string]any{"trace": route}, Summary: "traced"}}}
	var buf bytes.Buffer
	renderReport(&buf, r, "table", false, false)
	for _, s := range []string{"192.0.2.1", "203.0.113.9", "12.6 ms", "no ICMP reply (not proof of loss)", "destination reached"} {
		if !strings.Contains(buf.String(), s) {
			t.Errorf("missing %q in:\n%s", s, buf.String())
		}
	}
}

func TestRenderedSummaryAndVerbose(t *testing.T) {
	r := diag.Report{Version: "0.2.0", Target: "host.local", Command: "check", Results: []diag.Result{
		{Layer: 1, Name: "Physical", Status: diag.OK, Summary: "eth0 up", Data: map[string]any{"interface": "eth0", "speed_mbps": "1000", "operstate": "up", "carrier": "1"}},
		{Layer: 2, Name: "DataLink", Status: diag.Warn, Summary: "no neighbor", Data: map[string]any{"total": 0}},
	}}
	var normal, verbose bytes.Buffer
	renderReport(&normal, r, "text", false, false)
	renderReport(&verbose, r, "text", true, false)
	if strings.Contains(normal.String(), "speed_mbps:") || !strings.Contains(verbose.String(), "speed_mbps:") {
		t.Fatalf("verbosity not honored:\n%s\n%s", normal.String(), verbose.String())
	}
	if !strings.Contains(normal.String(), "WARN") || !strings.Contains(normal.String(), "Progress:") {
		t.Fatalf("stoplights / completed progress missing: %s", normal.String())
	}
	if strings.Contains(normal.String(), "\x1b[") {
		t.Fatal("color unexpectedly written to plain output")
	}
}

func TestRedirectSummary(t *testing.T) {
	r := diag.Result{Layer: 7, Name: "Application", Status: diag.OK, Summary: "HTTP 301 via HEAD",
		Data: map[string]any{"location": "https://example.com/"}}
	if !strings.Contains(keyResult(r), "-> https://example.com/") {
		t.Fatalf("missing redirect: %s", keyResult(r))
	}
}

func TestExitStatusForFailuresAndWarnings(t *testing.T) {
	results := []diag.Result{{Status: diag.Warn}, {Status: diag.OK}}
	if got := overall(results); got != diag.Warn {
		t.Fatal(got)
	}
	results = append(results, diag.Result{Status: diag.Fail})
	if got := overall(results); got != diag.Fail {
		t.Fatal(got)
	}
}

func TestRawIPv6AndSpeedTimeout(t *testing.T) {
	cfg, err := parseCLI("trace", []string{"2001:db8::1"})
	if err != nil || cfg.opts.Target != "2001:db8::1" {
		t.Fatalf("IPv6 target=%q err=%v", cfg.opts.Target, err)
	}
	cfg, err = parseCLI("speed", []string{"--timeout", "1s", "--url", "https://example.com/"})
	if err != nil || cfg.opts.Timeout.Seconds() != 1 {
		t.Fatalf("explicit timeout not honored: %v / %v", cfg.opts.Timeout, err)
	}
}

func TestPhysicalWiFiCompactDisplay(t *testing.T) {
	r := diag.Result{Name: "Physical", Data: map[string]any{
		"interface": "wlan0", "operstate": "up",
		"wifi": map[string]any{"signal_dbm": -77, "signal_quality": "poor"},
	}}
	text := keyResult(r)
	if !strings.Contains(text, "-77 dBm") || !strings.Contains(text, "poor") {
		t.Fatal(text)
	}
}

func TestCommandCategoriesAndSpeedtestAlias(t *testing.T) {
	var help bytes.Buffer
	usage(&help)
	for _, word := range []string{"ASSESSMENTS", "OSI LAYER DIAGNOSTICS", "INDIVIDUAL TESTS", "speedtest"} {
		if !strings.Contains(help.String(), word) {
			t.Fatalf("help missing %q", word)
		}
	}
	if tasks("speedtest") == nil || tasks("speed") == nil {
		t.Fatal("speedtest or legacy speed alias not recognized")
	}
	for _, cmd := range []string{"speedtest", "speed"} {
		cfg, err := parseCLI(cmd, []string{"--download-url", "https://example.com/payload", "--once"})
		if err != nil || cfg.opts.DownloadURL == "" || !cfg.once {
			t.Fatalf("%s: cfg=%+v err=%v", cmd, cfg, err)
		}
	}
}

func TestDHCPCLICommandDispatch(t *testing.T) {
	if got := tasks("dhcp"); len(got) != 1 {
		t.Fatalf("expected one passive DHCP task, got %d", len(got))
	}
}
func TestCLIParsesSNIComparison(t *testing.T) {
	cfg, err := parseCLI("tls", []string{"internal.example", "--connect-ip", "192.0.2.10", "--sni", "internal.example", "--compare-sni"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.opts.ConnectIP != "192.0.2.10" || cfg.opts.SNI != "internal.example" || !cfg.opts.CompareSNI {
		t.Fatalf("SNI flags not parsed: %+v", cfg.opts)
	}
}

func TestSpeedtestWarningAppearsInAssessment(t *testing.T) {
	for _, reason := range []string{"Speedtest service not confirmed", "sampled below expectation"} {
		report := diag.Report{Version: "0.4.0", Command: "speedtest", Target: "speed.example", Results: []diag.Result{{
			Layer: 7, Name: "Speedtest", Status: diag.Warn, Summary: reason,
		}}}
		got := assessment(report)
		if !strings.Contains(got, "incomplete or below") {
			t.Fatalf("assessment hides %q: %s", reason, got)
		}
		var out bytes.Buffer
		renderReport(&out, report, "text", false, false)
		if strings.Contains(out.String(), "No immediate errors detected") {
			t.Fatalf("warning hidden in output: %s", out.String())
		}
	}
}

func TestSNIFlagsRestrictedToTLSCommands(t *testing.T) {
	for _, command := range []string{"dns", "http", "l4", "speedtest"} {
		for _, flag := range [][]string{{"--sni", "service.example"}, {"--connect-ip", "192.0.2.10"}, {"--compare-sni"}} {
			args := append([]string{"service.example"}, flag...)
			if _, err := parseCLI(command, args); err == nil {
				t.Errorf("%s incorrectly accepted TLS option %v", command, flag)
			}
		}
	}
	for _, command := range []string{"check", "l6", "tls"} {
		if _, err := parseCLI(command, []string{"service.example", "--sni", "service.example", "--connect-ip", "192.0.2.10"}); err != nil {
			t.Errorf("%s should accept TLS diagnostics flags: %v", command, err)
		}
	}
}

func TestSpeedtestRequiresExplicitDestination(t *testing.T) {
	if _, err := parseCLI("speedtest", nil); err == nil {
		t.Fatal("speedtest without target unexpectedly contacted a default service")
	}
	cfg, err := parseCLI("speedtest", []string{"--download-url", "https://example.org/payload", "--once"})
	if err != nil || cfg.opts.Target != "example.org" || cfg.opts.URL != "" {
		t.Fatalf("download-only speedtest should not probe an unrelated portal: cfg=%+v err=%v", cfg, err)
	}
	if _, err = parseCLI("speedtest", []string{"--download-url", "https://alice:secret@example.org/payload"}); err == nil {
		t.Fatal("download URL with credentials accepted")
	}
}
