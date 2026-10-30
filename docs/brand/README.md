# Brand assets

The LinkedIn company cover, and the HTML it is rendered from. Keeping the
source here means the next size is a window-size argument rather than a redraw.

| File | Where it goes | Size |
|---|---|---|
| `stathe-linkedin-company-1128x191.png` | company page cover | 1128 × 191 |

The left is left clear: LinkedIn drops the page logo over the lower left of a
company cover.

## Palette

Sampled from `docs/banner.png` rather than guessed.

| | |
|---|---|
| Ink (background) | `#0a1420` |
| Glow (radial, top) | `#0b2a32` |
| Wordmark | `#e8eef4` |
| Accent (the square) | `#19c7b2` |
| Muted text | `#8ba3ad` |

## Rendering

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless --disable-gpu --hide-scrollbars \
  --window-size=1128,191 \
  --screenshot=docs/brand/stathe-linkedin-company-1128x191.png \
  "file://$PWD/docs/brand/company.html"
```

The window size is the image size, so a new format needs no new artwork.

## Open

`company.html` sets the wordmark in Helvetica Neue at weight 900.
`docs/banner.png` was drawn elsewhere in a heavier, more condensed face, so the
two are close but not identical. Naming the original typeface would let this
one match it.
