package main

import "github.com/ivanversluis/osidiag/internal/diag"

// A confirmed L1 failure invalidates dependent L2-L7 probes. Explicitly mark
// them skipped so JSON, text, tables and TUI report the same decision.
func executeLayer(command string, index int, l1Failed bool, fn diag.Task, opts diag.Options) diag.Result {
	if command == "check" && index > 0 && l1Failed {
		return diag.Result{
			Layer: index + 1, Name: layerName(index), Status: diag.Skipped,
			Summary: "Not run: L1 physical link failed",
			Data: map[string]any{"reason": "dependency", "blocked_by": "L1", "executed": false},
		}
	}
	return diag.Measure(fn, opts)
}
