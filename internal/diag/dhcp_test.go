package diag

import "testing"

func TestPassiveDHCPNeverClaimsActiveServerResponse(t *testing.T) {
	result := DHCPOnly(Options{Interface: "auto", Target: "localhost", Limit: 10})
	if result.Name != "DHCP" || result.Layer != 2 || result.Data["read_only"] != true {
		t.Fatalf("unexpected DHCP result: %+v", result)
	}
}
