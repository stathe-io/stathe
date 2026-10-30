# Brand assets

The LinkedIn covers, and the HTML they are rendered from. Keeping the source
here means the next size is a window-size argument rather than a redraw.

| File | Where it goes | Size |
|---|---|---|
| `stathe-linkedin-profile-from-banner.png` | personal profile background | 1584 × 396 |
| `stathe-linkedin-company-1128x191.png` | company page cover | 1128 × 191 |
| `stathe-linkedin-profile-1584x396.png` | alternative profile background | 1584 × 396 |

`stathe-linkedin-profile-from-banner.png` is cut from `docs/banner.png`, so the
wordmark is the real one rather than a near match, and the tagline underneath it
is gone. `makebanner.py` does it: it blends the tagline band away between a
clean row above and below (a flat fill leaves a visible rectangle in a radial
gradient), then crops a 4:1 window centred on the wordmark at y 157-346, then
area-averages down to 1584 × 396. The letters are never moved or redrawn.

Both leave the left clear: LinkedIn drops the page logo over the lower left of
a company cover, and a profile photo over the same corner of a background.

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

The two HTML-rendered files set the wordmark in Helvetica Neue at weight 900.
`docs/banner.png` was drawn elsewhere in a heavier, more condensed face, so
they are close but not identical -- which is why the file cut from the banner
exists, and why naming the original typeface would let the rest match it.
