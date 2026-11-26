package diag

// Shared diagnostic model: Linux and Windows must expose the same result types.
type EchoStats struct {
 Address string `json:"address"`
 Sent int `json:"sent"`
 Received int `json:"received"`
 LossPercent float64 `json:"loss_percent"`
 MinMS float64 `json:"min_ms,omitempty"`
 AvgMS float64 `json:"avg_ms,omitempty"`
 MaxMS float64 `json:"max_ms,omitempty"`
 Responses []Probe `json:"responses"`
}
type Probe struct {
 Responder string `json:"responder,omitempty"`
 Reply string `json:"reply"`
 RTTMS float64 `json:"rtt_ms,omitempty"`
 Timeout bool `json:"timeout,omitempty"`
 Reached bool `json:"reached"`
}
type TraceHop struct {
 TTL int `json:"ttl"`
 Probes []Probe `json:"probes"`
 LossPercent float64 `json:"loss_percent"`
 Reached bool `json:"reached"`
}
type TraceStats struct {
 Address string `json:"address"`
 Hops []TraceHop `json:"hops"`
 Reached bool `json:"reached"`
 Note string `json:"note"`
}
