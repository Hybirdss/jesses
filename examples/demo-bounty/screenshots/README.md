# screenshots/

Real-run screenshots of `jesses verify`, `jesses stats`, `jesses show`.

## Files

| File | Source |
|---|---|
| `hero.svg` | hand-authored triptych — session → seal → verify (not a terminal capture) |
| `verify.svg` | `jesses verify --offline --report report.md session.jes` |
| `stats.svg` | `jesses stats session.jes` |
| `show.svg` | `jesses show session.jes` |
| `*.ansi` | raw ANSI-escaped captures (source for each terminal SVG) |
| `ansi2svg.py` | zero-dependency Python script that converts ANSI → SVG |

`hero.svg` is the only non-capture here. It's an illustrative flow diagram using the same color palette as the ANSI captures, with SMIL animations (moving packet along the arrows, subtle pulse on the deny row and the G5 failure). It's the hero image at the top of the root README. Edit it by hand.

## Regenerating

```bash
cd examples/demo-bounty
./reproduce.sh                                   # produces session.jes etc.

LC_ALL=C script -qc "./jesses verify --offline --report report.md session.jes" \
  screenshots/verify.ansi
LC_ALL=C script -qc "./jesses stats session.jes" \
  screenshots/stats.ansi
LC_ALL=C script -qc "./jesses show session.jes" \
  screenshots/show.ansi

for f in verify stats show; do
  # strip script(1)'s header + trailer lines + CR
  sed -i '1d;$d; s/\r$//' screenshots/$f.ansi
done

python3 screenshots/ansi2svg.py screenshots/verify.ansi screenshots/verify.svg \
  "jesses verify --offline --report report.md session.jes"
python3 screenshots/ansi2svg.py screenshots/stats.ansi screenshots/stats.svg \
  "jesses stats session.jes"
python3 screenshots/ansi2svg.py screenshots/show.ansi screenshots/show.svg \
  "jesses show session.jes"
```

`LC_ALL=C` forces `script(1)` to emit English header/footer lines (`Script started` / `Script done`) instead of locale-specific text, which the `sed '1d;$d'` invocation then reliably strips.

## Why SVG

- GitHub renders SVG inline in markdown (no external image host required)
- Text is selectable in the rendered image (copy-paste friendly)
- Vector scales cleanly on retina / 4K displays
- No external font files — uses the generic `ui-monospace` stack so it falls back gracefully on any OS
- Zero binary dependencies to maintain — the entire pipeline is `script` + Python stdlib
