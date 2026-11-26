package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/ivanversluis/osidiag/internal/diag"
)

type tuiModel struct {
	report   diag.Report
	running  bool
	total    int
	selected int
	scroll   int
	verbose  bool
	frame    int
	color    bool
}

func tuiHeader(w io.Writer, title, target string, color bool) {
	fmt.Fprintln(w, colorize("networknet.nl", themeWhite, color)+"  "+colorize("│", themeOrange, color)+"  "+colorize("INFRA / SEC / OPS", themeMuted, color)+"     "+colorize("OSIDIAG "+version, themeOrange, color))
	fmt.Fprintln(w, colorize(strings.Repeat("━", tableWidth()-2), themeOrange, color))
	fmt.Fprintf(w, "  %s   %s\n\n", colorize(title, themeOrange, color), colorize(target, themeWhite, color))
}

func tuiPanel(w io.Writer, title string, content []string, color bool) {
	fmt.Fprintln(w, colorize("  "+title, themeOrange, color))
	for _, line := range content {
		fmt.Fprintln(w, "    "+colorize(line, themeWhite, color))
	}
	fmt.Fprintln(w)
}

// renderTUISnapshot is side-effect free except for writing its output. Tests
// exercise it without requiring a terminal or any network access.
func renderTUISnapshot(w io.Writer, m tuiModel) {
	tuiHeader(w, "OSI DIAGNOSTIC / MANAGER", m.report.Target, m.color)
	ok, warn, fail := statusCounts(m.report.Results)
	pending := m.total - len(m.report.Results)
	state := "COMPLETE"
	if m.running {
		state = "SCANNING"
	}
	fmt.Fprintf(w, "  %s  %d/%d completed    %s OK   %s WARN   %s FAIL\n",
		colorize(state, themeOrange, m.color), len(m.report.Results), m.total,
		colorize(fmt.Sprint(ok), themeGreen, m.color), colorize(fmt.Sprint(warn), themeOrange, m.color), colorize(fmt.Sprint(fail), themeRed, m.color))
	const barWidth = 26
	done := 0
	if m.total > 0 {
		done = barWidth * len(m.report.Results) / m.total
	}
	fmt.Fprintf(w, "  [%s%s] %d%%\n\n",
		colorize(strings.Repeat("█", done), themeOrange, m.color),
		colorize(strings.Repeat("░", barWidth-done), themeMuted, m.color),
		func() int {
			if m.total == 0 {
				return 100
			}
			return 100 * len(m.report.Results) / m.total
		}())
	tableData := append([]diag.Result{}, m.report.Results...)
	if pending > 0 && m.report.Command == "check" {
		for i := len(tableData); i < m.total; i++ {
			tableData = append(tableData, diag.Result{Layer: i + 1, Name: layerName(i), Status: "--", Summary: "Pending..."})
		}
	}
	renderOSITable(w, tableData, m.color)
	fmt.Fprintln(w)
	if m.selected > 0 {
		contents := []string{}
		for _, r := range m.report.Results {
			if r.Layer != m.selected {
				continue
			}
			raw, _ := json.MarshalIndent(r.Data, "", "  ")
			contents = append(contents, strings.Split(string(raw), "\n")...)
			if r.Error != "" {
				contents = append(contents, "ERROR: "+r.Error)
			}
		}
		if len(contents) == 0 {
			contents = []string{"No detail available for this layer yet."}
		}
		from := m.scroll
		if from > len(contents)-1 {
			from = len(contents) - 1
		}
		if from < 0 {
			from = 0
		}
		to := from + 9
		if to > len(contents) {
			to = len(contents)
		}
		tuiPanel(w, fmt.Sprintf("L%d / DETAILS (%d-%d OF %d)", m.selected, from+1, to, len(contents)), contents[from:to], m.color)
	} else {
		cidr, mac, gw, gwmac, iface := "—", "—", "—", "—", "—"
		for _, r := range m.report.Results {
			if r.Layer == 2 {
				if v, ok := value(r, "local_mac").(string); ok {
					mac = v
				}
				if v, ok := value(r, "gateway_mac").(string); ok {
					gwmac = v
				}
			}
			if r.Layer == 3 {
				if v, ok := value(r, "local_cidr").(string); ok {
					cidr = v
				}
				if v, ok := value(r, "default_gateway").(string); ok {
					gw = v
				}
				if v, ok := value(r, "interface").(string); ok {
					iface = v
				}
			}
		}
		contents := []string{
			fmt.Sprintf("Interface  %-8s IP/CIDR  %s", iface, cidr),
			fmt.Sprintf("Local MAC  %-18s Default gateway  %s", mac, gw),
		}
		if gwmac != "—" {
			contents = append(contents, "Gateway MAC  "+gwmac)
		}
		tuiPanel(w, "LOCAL / ROUTE CONTEXT", contents, m.color)
	}
	assess := "Collecting measurements. The first failed layer is typically the most actionable."
	if !m.running {
		assess = assessment(m.report)
	}
	fmt.Fprintln(w, colorize("  ASSESSMENT", themeOrange, m.color))
	for _, line := range wrapCell(assess, tableWidth()-6) {
		fmt.Fprintln(w, "    "+colorize(line, themeWhite, m.color))
	}
	fmt.Fprintln(w)
	keys := "  [1-7] details   [0] overview   [j/k] scroll   [r] rerun   [v] details   [q] quit"
	if m.verbose {
		keys += "  (details enabled)"
	}
	fmt.Fprintln(w, colorize(keys, themeMuted, m.color))
}

// runCheckTUI uses the alternate screen and native raw keyboard. In a
// non-interactive environment it refuses to emit terminal control sequences.
func runCheckTUI(command string, cfg cliSettings, actions []diag.Task, stdout, stderr io.Writer) int {
	if !isTerminal(stdout) || !isTerminal(os.Stdin) {
		fmt.Fprintln(stderr, "osidiag: --output tui requires an interactive terminal; use --output table or json")
		return 2
	}
	restore, err := rawKeyboard()
	if err != nil {
		fmt.Fprintln(stderr, "osidiag: cannot open terminal UI:", err)
		return 2
	}
	defer restore()
	colors := !cfg.noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	fmt.Fprint(stdout, "\x1b[?1049h\x1b[?25l")
	defer fmt.Fprint(stdout, "\x1b[?25h\x1b[?1049l")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	keys := keyboardEvents()
	m := tuiModel{
		report:  diag.Report{Version: version, Timestamp: time.Now().UTC().Format(time.RFC3339), Target: cfg.opts.Target, Command: command},
		running: true, total: len(actions), color: colors,
	}
	var results chan diag.Result
	start := func() {
		m.running = true
		m.report.Results = nil
		m.selected, m.scroll = 0, 0
		results = make(chan diag.Result, len(actions))
		go func(out chan<- diag.Result) {
			l1Failed := false
			for i, fn := range actions {
				r := executeLayer(command, i, l1Failed, fn, cfg.opts)
				if i == 0 && r.Status == diag.Fail { l1Failed = true }
				out <- r
			}
		}(results)
	}
	start()
	ticker := time.NewTicker(160 * time.Millisecond)
	defer ticker.Stop()
	redraw := func() {
		var b bytes.Buffer
		renderTUISnapshot(&b, m)
		fmt.Fprint(stdout, "\x1b[H\x1b[2J")
		if colors {
			fmt.Fprint(stdout, themeBg)
		}
		fmt.Fprint(stdout, b.String())
		if colors {
			fmt.Fprint(stdout, colorReset)
		}
	}
	redraw()
	for {
		select {
		case r := <-results:
			m.report.Results = append(m.report.Results, r)
			if len(m.report.Results) == m.total {
				m.running = false
			}
			redraw()
		case key, ok := <-keys:
			if !ok {
				return tuiExitStatus(m.report, cfg.strict)
			}
			switch {
			case key == 'q' || key == 'Q':
				if m.running {
					return 130
				}
				return tuiExitStatus(m.report, cfg.strict)
			case key == 'r' || key == 'R':
				if !m.running {
					start()
					redraw()
				}
			case key == 'v' || key == 'V':
				m.verbose = !m.verbose
				if m.verbose && m.selected == 0 {
					m.selected = 1
				}
				if !m.verbose {
					m.selected = 0
				}
				m.scroll = 0
				redraw()
			case key == '0' || key == 27:
				m.selected, m.scroll = 0, 0
				redraw()
			case key >= '1' && key <= '7':
				m.selected = int(key - '0')
				m.scroll = 0
				redraw()
			case key == 'j':
				m.scroll++
				redraw()
			case key == 'k':
				if m.scroll > 0 {
					m.scroll--
				}
				redraw()
			}
		case <-ticker.C:
			if m.running {
				m.frame++
				redraw()
			}
		case <-ctx.Done():
			return 130
		}
	}
}

func tuiExitStatus(report diag.Report, strict bool) int {
	for _, r := range report.Results {
		if r.Status == diag.Fail || (strict && r.Status == diag.Warn) {
			return 1
		}
	}
	return 0
}
