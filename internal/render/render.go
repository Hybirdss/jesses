// Package render holds the shared terminal-output primitives the
// jesses CLI uses to draw its verify report, stats dashboard, and
// envelope viewer.
//
// Zero external dependencies. Colors are auto-disabled when stdout
// is not a terminal, when the NO_COLOR environment variable is set
// ([no-color.org] convention), or when the caller passes --ascii.
package render

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// Style toggles visual options. Construct via NewStyle; the zero
// value renders plain ASCII with no colors.
type Style struct {
	Color bool
	ASCII bool // force ASCII (no box-drawing, no bar graphics)
}

// NewStyle probes the environment for terminal + NO_COLOR + ASCII
// preferences. stream is usually os.Stdout.
func NewStyle(stream *os.File) Style {
	s := Style{}
	if stream == nil {
		return s
	}
	fi, err := stream.Stat()
	if err != nil {
		return s
	}
	isTTY := (fi.Mode() & os.ModeCharDevice) != 0
	noColor := os.Getenv("NO_COLOR") != ""
	s.Color = isTTY && !noColor
	return s
}

// With returns a copy of s with ASCII forced on.
func (s Style) With(force Style) Style {
	if force.ASCII {
		s.ASCII = true
		s.Color = false
	}
	return s
}

// ANSI color helpers — emit escape sequences only when color is on.
const (
	reset     = "\x1b[0m"
	bold      = "\x1b[1m"
	dim       = "\x1b[2m"
	red       = "\x1b[31m"
	green     = "\x1b[32m"
	yellow    = "\x1b[33m"
	blue      = "\x1b[34m"
	magenta   = "\x1b[35m"
	cyan      = "\x1b[36m"
	brightRed = "\x1b[91m"
)

func (s Style) Red(v string) string       { return s.wrap(red, v) }
func (s Style) Green(v string) string     { return s.wrap(green, v) }
func (s Style) Yellow(v string) string    { return s.wrap(yellow, v) }
func (s Style) Blue(v string) string      { return s.wrap(blue, v) }
func (s Style) Magenta(v string) string   { return s.wrap(magenta, v) }
func (s Style) Cyan(v string) string      { return s.wrap(cyan, v) }
func (s Style) Dim(v string) string       { return s.wrap(dim, v) }
func (s Style) Bold(v string) string      { return s.wrap(bold, v) }
func (s Style) BoldRed(v string) string   { return s.wrap(bold+red, v) }
func (s Style) BoldGreen(v string) string { return s.wrap(bold+green, v) }

func (s Style) wrap(code, v string) string {
	if !s.Color {
		return v
	}
	return code + v + reset
}

// ----------------------------------------------------------------------------
// Box drawing
// ----------------------------------------------------------------------------

// Box characters — unicode when ASCII mode is off.
type boxChars struct {
	tl, tr, bl, br, h, v, lt, rt, lc, rc string
}

var boxUnicode = boxChars{
	tl: "╭", tr: "╮", bl: "╰", br: "╯",
	h: "─", v: "│",
	lt: "├", rt: "┤", lc: "┬", rc: "┴",
}

var boxASCII = boxChars{
	tl: "+", tr: "+", bl: "+", br: "+",
	h: "-", v: "|",
	lt: "+", rt: "+", lc: "+", rc: "+",
}

func (s Style) boxc() boxChars {
	if s.ASCII {
		return boxASCII
	}
	return boxUnicode
}

// Section is one labelled group of lines inside a Box.
type Section struct {
	Label string   // shown in the section separator ("mandatory", "advisory", ...)
	Lines []string // rendered lines (already colored if desired)
}

// Box renders a titled box with one or more labelled sections.
// width is the inner width (excluding borders). Content lines that
// exceed width are truncated with an ellipsis; callers should size
// lines appropriately.
func (s Style) Box(title string, sections []Section, width int) string {
	b := s.boxc()
	var sb strings.Builder

	// Top border with embedded title.
	sb.WriteString(b.tl)
	sb.WriteString(topBorderWithTitle(title, width, b))
	sb.WriteString(b.tr)
	sb.WriteString("\n")

	for i, sec := range sections {
		if sec.Label != "" {
			// Section divider with embedded label: ├─ label ─────┤
			sb.WriteString(b.lt)
			label := " " + s.Dim(sec.Label) + " "
			pre := b.h
			post := strings.Repeat(b.h, width-visLen(label)-1)
			sb.WriteString(pre)
			sb.WriteString(label)
			sb.WriteString(post)
			sb.WriteString(b.rt)
			sb.WriteString("\n")
		} else if i > 0 {
			// Plain divider between untitled sections.
			sb.WriteString(b.lt)
			sb.WriteString(strings.Repeat(b.h, width))
			sb.WriteString(b.rt)
			sb.WriteString("\n")
		}
		for _, line := range sec.Lines {
			sb.WriteString(b.v)
			sb.WriteString(" ")
			sb.WriteString(padToVisLen(line, width-2))
			sb.WriteString(" ")
			sb.WriteString(b.v)
			sb.WriteString("\n")
		}
	}

	// Bottom border.
	sb.WriteString(b.bl)
	sb.WriteString(strings.Repeat(b.h, width))
	sb.WriteString(b.br)
	sb.WriteString("\n")

	return sb.String()
}

func topBorderWithTitle(title string, width int, b boxChars) string {
	if title == "" {
		return strings.Repeat(b.h, width)
	}
	inner := " " + title + " "
	if visLen(inner) >= width {
		return strings.Repeat(b.h, width)
	}
	// Pad title to the RIGHT with horizontal rules.
	return b.h + b.h + inner + strings.Repeat(b.h, width-visLen(inner)-2)
}

// ----------------------------------------------------------------------------
// Bars
// ----------------------------------------------------------------------------

// BarChar is the block used to draw filled portions of a bar.
const BarChar = "█"

// BarEmpty is the block for the unfilled portion.
const BarEmpty = "░"

// Bar renders a count relative to a maximum as an ASCII/unicode bar
// of total visual width. When filled == max the whole bar is filled;
// when filled == 0 the whole bar is empty blocks.
func (s Style) Bar(filled, max, width int) string {
	if width < 1 {
		return ""
	}
	if max < 1 {
		max = 1
	}
	if filled < 0 {
		filled = 0
	}
	if filled > max {
		filled = max
	}
	f := filled * width / max
	if f == 0 && filled > 0 {
		f = 1
	}
	e := width - f
	full := BarChar
	empty := BarEmpty
	if s.ASCII {
		full = "#"
		empty = "."
	}
	return strings.Repeat(full, f) + strings.Repeat(empty, e)
}

// ----------------------------------------------------------------------------
// Gate marks
// ----------------------------------------------------------------------------

// GatePass returns the ✓ mark (green when color is on).
func (s Style) GatePass() string { return s.Green(checkOr(s.ASCII, "✓", "OK")) }

// GateFail returns the ✗ mark (bold red when color is on).
func (s Style) GateFail() string { return s.BoldRed(checkOr(s.ASCII, "✗", "!!")) }

// GateAdvisory returns the ⚠ mark (yellow when color is on).
func (s Style) GateAdvisory() string { return s.Yellow(checkOr(s.ASCII, "⚠", "~~")) }

// DecisionChip returns a compact colored chip for an event decision.
func (s Style) DecisionChip(decision string) string {
	d := strings.ToLower(decision)
	label := strings.ToUpper(decision)
	switch d {
	case "allow":
		return s.Green(label)
	case "deny":
		return s.BoldRed(label)
	case "warn":
		return s.Yellow(label)
	case "commit":
		return s.Cyan(label)
	}
	return s.Dim(label)
}

// ----------------------------------------------------------------------------
// Duration + hex truncation helpers
// ----------------------------------------------------------------------------

// Duration formats a time.Duration human-friendly (2m 14s, 1h 5m, 125ms).
func Duration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int((d - time.Duration(m)*time.Minute).Seconds())
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	}
	h := int(d.Hours())
	m := int((d - time.Duration(h)*time.Hour).Minutes())
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}

// HexTrunc returns the first n characters of s followed by "…" when
// s is longer than n. Used to shorten cryptographic hashes for
// display.
func HexTrunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ----------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------

// visLen returns the visible column width of s, skipping ANSI escape
// sequences and counting unicode glyphs as one cell each.
func visLen(s string) int {
	n := 0
	inEscape := false
	for _, r := range s {
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		if r == 0x1b {
			inEscape = true
			continue
		}
		n++
		_ = utf8.RuneLen(r)
	}
	return n
}

// padToVisLen pads s with spaces on the right so its visible length
// equals width; truncates with "…" when longer.
func padToVisLen(s string, width int) string {
	vl := visLen(s)
	if vl == width {
		return s
	}
	if vl < width {
		return s + strings.Repeat(" ", width-vl)
	}
	// Truncate: strip rune-by-rune. Preserves ANSI escapes at the
	// cost of some accuracy when escapes overlap with truncation.
	return truncate(s, width-1) + "…"
}

func truncate(s string, width int) string {
	var sb strings.Builder
	n := 0
	inEscape := false
	for _, r := range s {
		if n >= width && !inEscape {
			break
		}
		if inEscape {
			sb.WriteRune(r)
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		if r == 0x1b {
			inEscape = true
			sb.WriteRune(r)
			continue
		}
		sb.WriteRune(r)
		n++
	}
	return sb.String()
}

func checkOr(ascii bool, unicode, plain string) string {
	if ascii {
		return plain
	}
	return unicode
}
