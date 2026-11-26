package diag

import (
	"math"
	"testing"
	"time"
)

func TestCounterRatesOnlyReportDeltas(t *testing.T) {
	before := map[string]uint64{"rx_errors": 400, "tx_dropped": 20, "collisions": 9}
	after := map[string]uint64{"rx_errors": 410, "tx_dropped": 17, "collisions": 9}
	rates, unavailable := counterRates(before, after, 5*time.Second)
	if math.Abs(rates["rx_errors"]-2) > 0.001 || rates["collisions"] != 0 {
		t.Fatalf("incorrect rates: %v", rates)
	}
	if _, ok := rates["tx_dropped"]; ok || len(unavailable) != 1 || unavailable[0] != "tx_dropped" {
		t.Fatalf("counter reset treated as data: %v %v", rates, unavailable)
	}
	if c := counterCheck(rates, unavailable, "test"); c.Status != Warn {
		t.Fatalf("incrementing error counter must warn: %+v", c)
	}
	if c := counterCheck(map[string]float64{"rx_errors": 0}, nil, "test"); c.Status != OK {
		t.Fatalf("zero errors should pass: %+v", c)
	}
	if c := counterCheck(nil, nil, "test"); c.Status != Unknown {
		t.Fatalf("missing metrics are not a link failure: %+v", c)
	}
}

func TestSpeedNegotiationRequiresKnownExpectation(t *testing.T) {
	if c := speedCheck(100, 0, "test"); c.Status != OK {
		t.Fatalf("cannot assume every NIC is gigabit: %+v", c)
	}
	if c := speedCheck(100, 1000, "test"); c.Status != Warn {
		t.Fatalf("slow negotiated speed should warn when expected: %+v", c)
	}
	if c := speedCheck(0, 1000, "test"); c.Status != Unknown {
		t.Fatalf("unavailable speed should be unknown: %+v", c)
	}
}

func TestMergeLinkEvidencePreservesFailures(t *testing.T) {
	d := map[string]any{"interface": "eth0"}
	e := LinkEvidence{Fields: map[string]any{"kind": "ethernet"}, Checks: []LinkCheck{
		{"speed", Unknown, "unknown", "", ""},
		{"link", Warn, "degraded", "", ""},
	}}
	if got := mergeLinkEvidence(d, OK, e); got != Warn {
		t.Fatalf("expected warning, got %s", got)
	}
	if got := mergeLinkEvidence(d, Fail, e); got != Fail {
		t.Fatalf("warning masked link failure: %s", got)
	}
}
