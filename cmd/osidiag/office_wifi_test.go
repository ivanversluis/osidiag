package main

import (
	"testing"
	"time"
)

func TestOfficeWiFiCLIObservationWindow(t *testing.T) {
	for _,tc:=range []struct{args []string;good bool}{
		{[]string{"--wifi-sample","15s","--min-wifi-mbps","100"},true},
		{[]string{"--wifi-sample","30s"},true},
		{[]string{"--wifi-sample","0s"},true},
		{[]string{"--wifi-sample","9s"},false},
		{[]string{"--wifi-sample","31s"},false},
		{[]string{"--wifi-sample","-1s"},false},
		{[]string{"--min-wifi-mbps","-1"},false},
	} {
		cfg,err:=parseCLI("wifi",tc.args)
		if (err==nil)!=tc.good {t.Errorf("args=%v err=%v",tc.args,err)}
		if err==nil && len(tc.args)>1 && tc.args[0]=="--wifi-sample" && tc.args[1]=="15s" &&
			cfg.opts.WiFiSample!=15*time.Second {t.Fatalf("wrong window: %v",cfg.opts.WiFiSample)}
	}
}

func TestExplicitGatewayAndLLDPFlags(t *testing.T) {
	cfg,err:=parseCLI("l2",[]string{"--gateway-probe","--lldp"})
	if err!=nil || !cfg.opts.GatewayProbe || !cfg.opts.LLDP {
		t.Fatalf("L2 flags missing: %+v %v",cfg.opts,err)
	}
}
