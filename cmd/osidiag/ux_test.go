package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ivanversluis/osidiag/internal/diag"
)

func sampleNetworkReport() diag.Report {
	return diag.Report{Version: version, Command: "check", Target: "example.com",
		Results: []diag.Result{
			{Layer: 1, Name: "Physical", Status: diag.OK, Summary: "eth0 up", Data: map[string]any{"interface": "eth0", "operstate": "up", "carrier": "1", "speed_mbps": "10000", "mac": "28:c5:c8:bd:6c:5d"}},
			{Layer: 2, Name: "DataLink", Status: diag.OK, Summary: "one neighbor", Data: map[string]any{"interface": "eth0", "local_mac": "28:c5:c8:bd:6c:5d", "total": 1, "default_gateway": "172.16.20.254", "gateway_mac": "18:fd:74:7f:36:a4"}},
			{Layer: 3, Name: "Network", Status: diag.OK, Summary: "ping successful", Data: map[string]any{
				"interface": "eth0", "local_cidr": "172.16.20.1/24", "default_gateway": "172.16.20.254",
				"ping": diag.EchoStats{Address: "188.114.97.0", Sent: 3, Received: 3, AvgMS: 4.7}}},
			{Layer: 4, Name: "Transport", Status: diag.OK, Summary: "6 TCP listeners"},
			{Layer: 5, Name: "Session", Status: diag.OK, Summary: "0 TCP sessions"},
			{Layer: 6, Name: "Presentation", Status: diag.OK, Summary: "TLS valid"},
			{Layer: 7, Name: "Application", Status: diag.OK, Summary: "HTTP 200"},
		},
	}
}

func TestNiceTableIncludesMACRouteAndCIDR(t *testing.T) {
	report := sampleNetworkReport()
	var b bytes.Buffer
	renderReport(&b, report, "table", false, false)
	out := b.String()
	for _, value := range []string{"╭", "┼", "KEY OBSERVATION", "28:c5:c8:bd:6c:5d", "18:fd:74:7f:36:a4", "172.16.20.1/24", "172.16.20.254", "188.114.97.0", "Assessment:"} {
		if !strings.Contains(out, value) {
			t.Errorf("missing %q in\n%s", value, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("table emitted ANSI when color disabled")
	}
}

func TestNetworknetTerminalDashboard(t *testing.T) {
	r := sampleNetworkReport()
	m := tuiModel{report: r, total: 7, color: false}
	var b bytes.Buffer
	renderTUISnapshot(&b, m)
	out := b.String()
	for _, want := range []string{"networknet.nl", "INFRA / SEC / OPS", "OSI DIAGNOSTIC / MANAGER", "LOCAL / ROUTE CONTEXT", "172.16.20.1/24", "172.16.20.254", "[1-7] details", "100%"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	m.selected = 2
	b.Reset()
	renderTUISnapshot(&b, m)
	if !strings.Contains(b.String(), "L2 / DETAILS") || !strings.Contains(b.String(), "gateway_mac") {
		t.Errorf("no drilldown\n%s", b.String())
	}
}

func TestSpeedMonitorVisual(t *testing.T) {
	p := diag.SpeedProgress{State: "downloading", SampleLimit: 8 << 20,
		CurrentBytes: 4 << 20, CurrentMbps: 436.5, AverageMbps: 420.2, PeakMbps: 490.1, Completed: 4, TotalBytes: 32 << 20}
	var b bytes.Buffer
	renderSpeedPanel(&b, p, "https://speed.example/", "https://speed.cloudflare.com/__down?bytes=8388608", false)
	out := b.String()
	for _, value := range []string{"networknet.nl", "speed.cloudflare.com", "436.5", "420.2", "50%", "[q] quit", "32.0 MiB"} {
		if !strings.Contains(out, value) {
			t.Errorf("missing %q in\n%s", value, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("non-color dashboard emitted ANSI")
	}
}

func TestCheckDefaultsToTableAndSupportsTUI(t *testing.T) {
	cases := []struct {
		args   []string
		format string
	}{
		{nil, "table"},
		{[]string{"--output", "text"}, "text"},
		{[]string{"-o", "tui"}, "tui"},
		{[]string{"--json"}, "json"},
	}
	for _, tc := range cases {
		cfg, err := parseCLI("check", tc.args)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if cfg.format != tc.format {
			t.Errorf("%v: got %s want %s", tc.args, cfg.format, tc.format)
		}
	}
}

func TestSpeedMonitorCLIOptions(t *testing.T) {
	cfg, err := parseCLI("speed", []string{"--download-url", "https://example.com/payload", "--samples", "5", "--pause", "1s"})
	if err != nil || cfg.samples != 5 || cfg.pause.Seconds() != 1 {
		t.Fatalf("monitor flags: %+v err=%v", cfg, err)
	}
	invalid := [][]string{
		{"--watch"}, {"--watch", "--once"}, {"--samples", "-1", "--download-url", "https://example.com/payload"},
		{"--watch", "--output", "json", "--download-url", "https://example.com/payload"},
		{"--once", "--samples", "2", "--download-url", "https://example.com/payload"},
	}
	for _, args := range invalid {
		if _, err := parseCLI("speed", args); err == nil {
			t.Errorf("accepted invalid flags %v", args)
		}
	}
}

func TestInteractiveOutputRefusesNonTTY(t *testing.T) {
	var out, errs bytes.Buffer
	status := execute([]string{"check", "--output", "tui"}, &out, &errs)
	if status != 2 || !strings.Contains(errs.String(), "requires an interactive terminal") {
		t.Fatalf("expected TTY error, got %d / %q", status, errs.String())
	}
}
