package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/ivanversluis/osidiag/internal/diag"
)

func renderSpeedPanel(w io.Writer, p diag.SpeedProgress, portal, download string, color bool) {
	tuiHeader(w, "SPEEDTEST / INDEPENDENT HTTP MONITOR", portal, color)
	fmt.Fprintln(w, colorize("  CONTINUOUS BOUNDED DOWNLOAD", themeOrange, color))
	fmt.Fprintln(w, "  Endpoint  "+colorize(speedHost(download), themeWhite, color))
	fmt.Fprintln(w, "  Mode      bounded single HTTP stream; upload not measured")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", colorize("CURRENT", themeMuted, color))
	fmt.Fprintf(w, "  %s %s\n", colorize(fmt.Sprintf("%8.1f", p.CurrentMbps), themeOrange, color), colorize("Mbps", themeWhite, color))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  AVERAGE  %s     PEAK  %s     LAST  %.1f Mbps\n",
		colorize(fmt.Sprintf("%.1f Mbps", p.AverageMbps), themeGreen, color),
		colorize(fmt.Sprintf("%.1f Mbps", p.PeakMbps), themeOrange, color), p.LastMbps)
	fmt.Fprintln(w)
	limit := p.SampleLimit
	progress := 0
	if limit > 0 {
		progress = int(100 * p.CurrentBytes / limit)
	}
	if progress > 100 {
		progress = 100
	}
	const segments = 38
	done := segments * progress / 100
	fmt.Fprintf(w, "  SAMPLE  [%s%s] %3d%%\n",
		colorize(repeat("█", done), themeOrange, color),
		colorize(repeat("░", segments-done), themeMuted, color), progress)
	fmt.Fprintf(w, "  %s / %s MiB\n", formatMiB(p.CurrentBytes), formatMiB(limit))
	fmt.Fprintln(w)
	tuiPanel(w, "SESSION", []string{
		fmt.Sprintf("Samples    %d", p.Completed),
		fmt.Sprintf("Transferred  %s MiB", formatMiB(p.TotalBytes)),
		fmt.Sprintf("Elapsed      %.1f s", p.ElapsedSeconds),
		fmt.Sprintf("State        %s", p.State),
	}, color)
	if p.Error != "" {
		fmt.Fprintln(w, colorize("  ERROR", themeRed, color))
		fmt.Fprintln(w, "    "+p.Error)
	}
	fmt.Fprintln(w, colorize("  [q] quit  [Ctrl+C] stop  •  repeats until stopped or --samples is reached", themeMuted, color))
	fmt.Fprintln(w, colorize("  Each sample is capped. Continuous downloads use real data; this is not an upload or ISP line-speed test.", themeMuted, color))
}

func repeat(s string, count int) string {
	if count < 0 {
		count = 0
	}
	if count > 128 {
		count = 128
	}
	var b bytes.Buffer
	for i := 0; i < count; i++ {
		b.WriteString(s)
	}
	return b.String()
}
func formatMiB(n int64) string { return fmt.Sprintf("%.1f", float64(n)/(1<<20)) }
func speedHost(address string) string {
	u, err := url.Parse(address)
	if err != nil {
		return "invalid"
	}
	return u.Hostname()
}

func runSpeedMonitor(cfg cliSettings, stdout, stderr io.Writer) int {
	o := cfg.opts
	if o.DownloadURL == "" {
		fmt.Fprintln(stderr, "osidiag: continuous speed monitoring requires --download-url")
		return 2
	}
	interactive := isTerminal(stdout) && isTerminal(os.Stdin)
	if cfg.format == "tui" && !interactive {
		fmt.Fprintln(stderr, "osidiag: --output tui requires an interactive terminal; use --output table")
		return 2
	}
	tui := interactive && (cfg.format == "tui" || cfg.format == "text" || cfg.format == "table")
	colors := tui && !cfg.noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	if tui {
		restore, err := rawKeyboard()
		if err != nil {
			fmt.Fprintln(stderr, "osidiag: terminal input unavailable:", err)
			return 2
		}
		defer restore()
		fmt.Fprint(stdout, "\x1b[?1049h\x1b[?25l")
		defer func() {
			if tui {
				fmt.Fprint(stdout, "\x1b[?25h\x1b[?1049l")
			}
		}()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelManual := context.WithCancel(ctx)
	defer cancelManual()
	var keys <-chan byte
	if tui {
		keys = keyboardEvents()
	}
	progressCh := make(chan diag.SpeedProgress, 32)
	doneCh := make(chan diag.Result, 1)
	go func() {
		doneCh <- diag.WatchSpeed(ctx, o, cfg.samples, cfg.pause, func(p diag.SpeedProgress) {
			select {
			case progressCh <- p:
			default:
			}
		})
	}()
	current := diag.SpeedProgress{State: "initializing", SampleLimit: o.MaxBytes}
	lastPrintedSample := -1
	redraw := func() {
		if cfg.noProgress {
			return
		}
		if tui {
			var b bytes.Buffer
			renderSpeedPanel(&b, current, o.URL, o.DownloadURL, colors)
			fmt.Fprint(stdout, "\x1b[H\x1b[2J")
			if colors {
				fmt.Fprint(stdout, themeBg)
			}
			fmt.Fprint(stdout, b.String())
			if colors {
				fmt.Fprint(stdout, colorReset)
			}
		} else if isTerminal(stderr) {
			fmt.Fprintf(stderr, "\r\x1b[2Ksample %d | %.1f Mbps now | %.1f avg | %s MiB | Ctrl+C stops",
				current.Completed, current.CurrentMbps, current.AverageMbps, formatMiB(current.TotalBytes))
		} else if current.Completed != lastPrintedSample {
			fmt.Fprintf(stderr, "speed: %d sample(s), %.1f Mbps avg, %s MiB transferred\n",
				current.Completed, current.AverageMbps, formatMiB(current.TotalBytes))
			lastPrintedSample = current.Completed
		}
	}
	redraw()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	stopping := false
	cancelEvent := ctx.Done()
	for {
		select {
		case p := <-progressCh:
			current = p
			redraw()
		case <-ticker.C:
			if tui {
				redraw()
			}
		case key, ok := <-keys:
			if ok && (key == 'q' || key == 'Q' || key == 3) {
				stopping = true
				cancelManual()
			}
			if !ok {
				keys = nil
			}
		case <-cancelEvent:
			if !stopping {
				stopping = true
				cancelManual()
			}
			cancelEvent = nil
		case result := <-doneCh:
			// The alternate screen closes before the final copyable summary.
			if tui {
				fmt.Fprint(stdout, "\x1b[?25h\x1b[?1049l")
				tui = false
			} else if isTerminal(stderr) && !cfg.noProgress {
				fmt.Fprint(stderr, "\r\x1b[2K")
			}
			report := diag.Report{Version: version, Timestamp: time.Now().UTC().Format(time.RFC3339),
				Command: "speedtest", Target: o.Target, Results: []diag.Result{result}}
			renderReport(stdout, report, "table", cfg.verbose, false)
			if result.Status == diag.Fail || (result.Status == diag.Warn && cfg.strict) {
				return 1
			}
			return 0
		}
	}
}
