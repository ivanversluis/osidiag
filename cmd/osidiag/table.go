package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/ivanversluis/osidiag/internal/diag"
)

// Networknet palette, matching the site's graphite / white / amber visual
// language. No image assets or external UI libraries are required.
const (
	themeOrange = "\x1b[38;2;255;173;47m"
	themeWhite  = "\x1b[38;2;244;245;246m"
	themeMuted  = "\x1b[38;2;173;177;182m"
	themeLine   = "\x1b[38;2;93;96;102m"
	themeGreen  = "\x1b[38;2;110;221;145m"
	themeRed    = "\x1b[38;2;250;105;105m"
	themeBg     = "\x1b[48;2;23;25;27m"
	themePanel  = "\x1b[48;2;43;45;49m"
)

func colorize(s, code string, enabled bool) string {
	if !enabled {
		return s
	}
	return code + s + colorReset
}

func tableWidth() int {
	width := 102
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n >= 62 {
		width = n
	}
	if width < 76 {
		width = 76
	}
	if width > 124 {
		width = 124
	}
	return width
}

func padCell(s string, width int) string {
	runes := []rune(s)
	if len(runes) > width {
		return string(runes[:width-1]) + "…"
	}
	return s + strings.Repeat(" ", width-len(runes))
}

func wrapCell(s string, width int) []string {
	if width <= 1 {
		return []string{""}
	}
	words := strings.Fields(strings.ReplaceAll(s, "\n", " "))
	out := []string{}
	line := ""
	for _, word := range words {
		for len([]rune(word)) > width {
			if line != "" {
				out = append(out, line)
				line = ""
			}
			r := []rune(word)
			out = append(out, string(r[:width]))
			word = string(r[width:])
		}
		if line == "" {
			line = word
			continue
		}
		if len([]rune(line))+1+len([]rune(word)) > width {
			out = append(out, line)
			line = word
		} else {
			line += " " + word
		}
	}
	if line != "" {
		out = append(out, line)
	}
	if len(out) == 0 {
		out = append(out, "")
	}
	return out
}

func tableBorder(w io.Writer, left, middle, right string, widths []int, colored bool) {
	var b strings.Builder
	b.WriteString(left)
	for i, n := range widths {
		b.WriteString(strings.Repeat("─", n+2))
		if i+1 < len(widths) {
			b.WriteString(middle)
		}
	}
	b.WriteString(right)
	fmt.Fprintln(w, colorize(b.String(), themeLine, colored))
}

func renderOSITable(w io.Writer, results []diag.Result, color bool) {
	total := tableWidth()
	// Four columns: 5/13/6 fixed, plus a flexible key observation column.
	widths := []int{5, 13, 6, total - 5 - 13 - 6 - 13}
	if widths[3] < 35 {
		widths[3] = 35
	}
	tableBorder(w, "╭", "┬", "╮", widths, color)
	header := []string{"OSI", "DIAGNOSTIC", "STATE", "KEY OBSERVATION"}
	fmt.Fprintf(w, "%s %s %s %s %s %s %s %s %s\n",
		colorize("│", themeLine, color), colorize(padCell(header[0], widths[0]), themeOrange, color),
		colorize("│", themeLine, color), colorize(padCell(header[1], widths[1]), themeOrange, color),
		colorize("│", themeLine, color), colorize(padCell(header[2], widths[2]), themeOrange, color),
		colorize("│", themeLine, color), colorize(padCell(header[3], widths[3]), themeOrange, color),
		colorize("│", themeLine, color))
	tableBorder(w, "├", "┼", "┤", widths, color)
	for _, r := range results {
		lines := wrapCell(keyResult(r), widths[3])
		for i, line := range lines {
			layer, name, state := "", "", ""
			if i == 0 {
				layer, name, state = fmt.Sprintf("L%d", r.Layer), r.Name, strings.ToUpper(string(r.Status))
			}
			statusColor := themeWhite
			switch r.Status {
			case diag.OK:
				statusColor = themeGreen
			case diag.Warn:
				statusColor = themeOrange
			case diag.Fail:
				statusColor = themeRed
			}
			fmt.Fprintf(w, "%s %s %s %s %s %s %s %s %s\n",
				colorize("│", themeLine, color), colorize(padCell(layer, widths[0]), themeMuted, color),
				colorize("│", themeLine, color), colorize(padCell(name, widths[1]), themeWhite, color),
				colorize("│", themeLine, color), colorize(padCell(state, widths[2]), statusColor, color),
				colorize("│", themeLine, color), colorize(padCell(line, widths[3]), themeWhite, color),
				colorize("│", themeLine, color))
		}
	}
	tableBorder(w, "╰", "┴", "╯", widths, color)
}
