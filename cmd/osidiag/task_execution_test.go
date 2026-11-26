package main

import (
	"testing"
	"github.com/ivanversluis/osidiag/internal/diag"
)

func TestCheckSkipsDependentProbesAfterL1Failure(t *testing.T) {
	calls := 0
	failed := func(diag.Options) diag.Result {
		calls++
		return diag.Result{Layer: 1, Name: "Physical", Status: diag.Fail}
	}
	downstream := func(diag.Options) diag.Result {
		calls++
		return diag.Result{Layer: 2, Name: "DataLink", Status: diag.OK}
	}
	r1 := executeLayer("check", 0, false, failed, diag.Options{})
	r2 := executeLayer("check", 1, r1.Status == diag.Fail, downstream, diag.Options{})
	if calls != 1 || r2.Status != diag.Skipped || r2.Layer != 2 {
		t.Fatalf("L1 failure should skip L2: calls=%d layer=%d status=%s", calls, r2.Layer, r2.Status)
	}
	if r2.Data["blocked_by"] != "L1" || r2.Data["executed"] != false {
		t.Fatalf("missing machine-readable skip evidence: %#v", r2.Data)
	}
	r3 := executeLayer("l2", 1, true, downstream, diag.Options{})
	if calls != 2 || r3.Status != diag.OK {
		t.Fatalf("explicit L2 command unexpectedly blocked: %#v", r3)
	}
}

func TestWeakWiFiMustNotSkipHigherLayers(t *testing.T) {
	calls := 0
	layer := func(diag.Options) diag.Result {
		calls++
		return diag.Result{Layer: 2, Name: "DataLink", Status: diag.OK}
	}
	_ = executeLayer("check", 1, false, layer, diag.Options{})
	if calls != 1 {
		t.Fatal("warning-level signal should not stop connectivity diagnosis")
	}
}
