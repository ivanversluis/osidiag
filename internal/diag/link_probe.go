package diag

import (
	"fmt"
	"sort"
	"time"
)

// Unknown means the operating system did not expose enough evidence to assess
// an individual check. Skipped is reserved for unexecuted higher-layer probes.
const (
	Unknown Status = "unknown"
	Skipped Status = "skipped"
)

// LinkCheck is the stable, platform-independent contract for L1 evidence.
// Unavailable measurements are explicitly unknown, never fabricated as healthy.
type LinkCheck struct {
	Name     string `json:"name"`
	Status   Status `json:"status"`
	Value    any    `json:"value"`
	Evidence string `json:"evidence"`
	Hint     string `json:"hint,omitempty"`
}

type LinkEvidence struct {
	Fields map[string]any
	Checks []LinkCheck
}

// LinkProbe implementations are separated by build tags. Both report the
// currently selected interface, rather than guessing an unrelated physical NIC.
type LinkProbe interface {
	Probe(Options, string) LinkEvidence
}

func mergeLinkEvidence(data map[string]any, status Status, e LinkEvidence) Status {
	for k, v := range e.Fields {
		data[k] = v
	}
	data["checks"] = e.Checks
	for _, c := range e.Checks {
		switch c.Status {
		case Fail:
			return Fail
		case Warn:
			if status == OK {
				status = Warn
			}
		}
	}
	return status
}

// counterRates computes actual per-second rates from two readings. A reset,
// rollover or a missing counter invalidates that rate, not the whole link.
func counterRates(before, after map[string]uint64, elapsed time.Duration) (map[string]float64, []string) {
	rates := make(map[string]float64)
	unknown := []string{}
	keys := make([]string, 0, len(before))
	for k := range before {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		end, ok := after[k]
		if !ok || elapsed <= 0 || end < before[k] {
			unknown = append(unknown, k)
			continue
		}
		rates[k] = float64(end-before[k]) / elapsed.Seconds()
	}
	return rates, unknown
}

func counterCheck(rates map[string]float64, unavailable []string, source string) LinkCheck {
	if len(rates) == 0 {
		return LinkCheck{"link_errors", Unknown, "unknown", source,
			"Counter sampling is unavailable; check OS or driver support."}
	}
	bad := false
	for _, field := range []string{"rx_errors", "tx_errors", "rx_dropped", "tx_dropped", "rx_crc_errors", "rx_frame_errors", "collisions"} {
		if rates[field] > 0 {
			bad = true
		}
	}
	if bad {
		return LinkCheck{"link_errors", Warn, rates, source,
			"Link errors or drops increased during the sample; investigate cable, duplex, driver and congestion."}
	}
	if len(unavailable) > 0 {
		return LinkCheck{"link_errors", Unknown, rates, source,
			fmt.Sprintf("Some counters reset or are unavailable: %v", unavailable)}
	}
	return LinkCheck{"link_errors", OK, rates, source, ""}
}

func speedCheck(mbps float64, minimum float64, source string) LinkCheck {
	if mbps <= 0 {
		return LinkCheck{"link_speed", Unknown, "unknown", source,
			"Link speed is not exposed by this driver."}
	}
	if minimum > 0 && mbps < minimum {
		return LinkCheck{"link_speed", Warn, mbps, source,
			fmt.Sprintf("Negotiated %.0f Mbps below configured minimum %.0f Mbps; inspect cable/port negotiation.", mbps, minimum)}
	}
	return LinkCheck{"link_speed", OK, mbps, source, ""}
}
