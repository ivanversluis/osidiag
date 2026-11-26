package diag

import "testing"

func TestGatewayNeighborCacheDoesNotClaimReachability(t *testing.T) {
	for _,tc:=range []struct {mac,state string;want Status}{
		{"00:01:02:03:04:05","REACHABLE",OK},
		{"00:01:02:03:04:05","STALE",OK},
		{"00:01:02:03:04:05","DYNAMIC",Unknown},
		{"00:01:02:03:04:05","FAILED",Warn},
		{"","",Unknown},
	} {
		c:=gatewayCacheStatus("192.0.2.1",tc.mac,tc.state,"test")
		if c.Status!=tc.want {t.Errorf("%s mac=%s got %s, want %s",tc.state,tc.mac,c.Status,tc.want)}
	}
	if c:=gatewayCacheStatus("on-link","","","test");c.Status!=Unknown {t.Fatalf("on-link should be unknown: %+v",c)}
}

func TestLLDPOutputSanitization(t *testing.T) {
	if got:=safeLinkText("switch-42");got!="switch-42" {t.Fatal(got)}
	if got:=safeLinkText("switch\x1b[31m");got!="unknown" {t.Fatalf("terminal escape leaked: %q",got)}
}
