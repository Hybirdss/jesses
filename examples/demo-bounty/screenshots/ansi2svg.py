#!/usr/bin/env python3
"""Convert ANSI-escaped terminal text (UTF-8) to a self-contained SVG.

Usage: ansi2svg.py input.txt output.svg [title]
"""
import re
import sys
from html import escape

# 8-color + bright palette mapping. Matches typical dark-terminal theme.
COLORS = {
    "30": "#5a5a5a",  # black (dim)
    "31": "#e55c5c",  # red
    "32": "#5fd37a",  # green
    "33": "#e8b14a",  # yellow
    "34": "#7fb3ff",  # blue
    "35": "#d685e8",  # magenta
    "36": "#6ecfd9",  # cyan
    "37": "#dde4ee",  # white
    "91": "#ff7070",  # bright red
    "92": "#80e89a",
    "93": "#ffd166",
    "94": "#a5c6ff",
    "95": "#e9a9f3",
    "96": "#8fe0ea",
    "97": "#ffffff",
}

DIM = "#8895a6"

ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")


def tokenize(s):
    pos = 0
    for m in ANSI_RE.finditer(s):
        if m.start() > pos:
            yield ("text", s[pos : m.start()])
        codes = m.group(1) or "0"
        yield ("code", codes)
        pos = m.end()
    if pos < len(s):
        yield ("text", s[pos:])


def convert(text, title="jesses"):
    # 80 chars @ 8.6 px width · 1.5x line height at 14px ≈ 22 px line height
    line_h = 22
    char_w = 8.8
    pad = 16
    lines = text.split("\n")
    # Trim trailing empty lines
    while lines and lines[-1].strip() == "":
        lines.pop()
    max_cols = 90
    for line in lines:
        plain = ANSI_RE.sub("", line)
        if len(plain) > max_cols:
            max_cols = len(plain)

    width = int(pad * 2 + max_cols * char_w)
    height = int(pad * 2 + (len(lines) + 2) * line_h)

    out = []
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" font-family="ui-monospace, Menlo, Consolas, monospace" '
        'font-size="14">'
    )
    out.append(
        f'<rect width="{width}" height="{height}" rx="8" fill="#0b0d10"/>'
    )
    # Traffic-lights + title bar
    out.append('<g transform="translate(16 14)">')
    for i, c in enumerate(["#ff6058", "#ffbd2e", "#27c93f"]):
        out.append(f'<circle cx="{i*18}" cy="6" r="6" fill="{c}"/>')
    if title:
        out.append(
            f'<text x="{max_cols * char_w / 2 - len(title)*4}" y="10" '
            'fill="#8895a6" font-size="12">' + escape(title) + "</text>"
        )
    out.append("</g>")

    y = pad + 24
    for line in lines:
        y += line_h
        x = pad
        cur_fill = "#dde4ee"
        cur_weight = "normal"
        cur_opacity = "1"
        for tag, val in tokenize(line):
            if tag == "code":
                for c in val.split(";"):
                    if c == "" or c == "0":
                        cur_fill = "#dde4ee"
                        cur_weight = "normal"
                        cur_opacity = "1"
                    elif c == "1":
                        cur_weight = "bold"
                    elif c == "2":
                        cur_opacity = "0.55"
                    elif c in COLORS:
                        cur_fill = COLORS[c]
            else:
                if val == "":
                    continue
                # SVG doesn't know about column advance for tspans without
                # explicit dx; emit each chunk at the running x.
                tstr = escape(val)
                attrs = f'fill="{cur_fill}"'
                if cur_weight != "normal":
                    attrs += f' font-weight="{cur_weight}"'
                if cur_opacity != "1":
                    attrs += f' opacity="{cur_opacity}"'
                out.append(
                    f'<text x="{x:.1f}" y="{y}" {attrs} xml:space="preserve">{tstr}</text>'
                )
                x += len(val) * char_w
    out.append("</svg>")
    return "\n".join(out)


def main():
    if len(sys.argv) < 3:
        print("usage: ansi2svg.py input.txt output.svg [title]", file=sys.stderr)
        sys.exit(2)
    inp, outp = sys.argv[1], sys.argv[2]
    title = sys.argv[3] if len(sys.argv) > 3 else "jesses"
    with open(inp, "rb") as f:
        raw = f.read().decode("utf-8", errors="replace")
    svg = convert(raw, title)
    with open(outp, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"wrote {outp}")


if __name__ == "__main__":
    main()
